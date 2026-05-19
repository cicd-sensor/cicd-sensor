package manager

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
)

var collectorTestSecret = managerauth.TokenPrefix + strings.Repeat("s", 64)

const collectorIngestProcedure = "/cicd_sensor.manager.v1.CollectorService/Ingest"

// TestAuthMiddleware_RejectsMissingToken is the direct regression pin for
// the prior UnaryInterceptorFunc bypass class: auth runs at the HTTP layer
// so all manager RPCs share one auth boundary. The middleware rejects the
// request before the wrapped handler runs, and emits an audit log for the
// failed attempt.
func TestAuthMiddleware_RejectsMissingToken(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	tokens := NewTokenStore([]string{collectorTestSecret})

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	server := newManagerHTTPTestServer(t, newAuthMiddleware(logger, tokens).Wrap(inner))
	defer server.Close()

	// Simulate an RPC path so procedure extraction lands in the audit log.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		server.URL+collectorIngestProcedure, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate: got %q, want Bearer", got)
	}
	if called {
		t.Fatal("inner handler was invoked despite auth failure")
	}
	if !strings.Contains(logBuf.String(), "manager_auth_failed") {
		t.Fatalf("audit log missing: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "CollectorService/Ingest") {
		t.Fatalf("audit log missing procedure: %s", logBuf.String())
	}
}

// TestAuthMiddleware_RejectsBadToken pins token mismatch rejection. The
// stored hash and the provided token differ, so even a well-formed bearer
// header must fail closed.
func TestAuthMiddleware_RejectsBadToken(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	tokens := NewTokenStore([]string{collectorTestSecret})

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler must not be invoked on bad token")
	})

	server := newManagerHTTPTestServer(t, newAuthMiddleware(logger, tokens).Wrap(inner))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		server.URL+collectorIngestProcedure, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", managerBearer(managerauth.TokenPrefix+strings.Repeat("x", 64)))

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate: got %q, want Bearer", got)
	}
}

// TestAuthMiddleware_AcceptsValidToken pins that a well-formed request with
// a matching secret reaches the inner handler. No audit log is emitted for
// successful auth by design; successes are high-volume and silent.
func TestAuthMiddleware_AcceptsValidToken(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	tokens := NewTokenStore([]string{collectorTestSecret})

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	server := newManagerHTTPTestServer(t, newAuthMiddleware(logger, tokens).Wrap(inner))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		server.URL+collectorIngestProcedure, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", managerBearer(collectorTestSecret))

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !called {
		t.Fatal("inner handler was not invoked on valid token")
	}
	if strings.Contains(logBuf.String(), "manager_auth_failed") {
		t.Fatalf("no audit log expected on success: %s", logBuf.String())
	}
}

func TestAuthMiddleware_AcceptsAnyRotationToken(t *testing.T) {
	secondarySecret := managerauth.TokenPrefix + strings.Repeat("t", 64)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	tokens := NewTokenStore([]string{collectorTestSecret, secondarySecret})

	for _, token := range []string{collectorTestSecret, secondarySecret} {
		t.Run(token[len(managerauth.TokenPrefix):len(managerauth.TokenPrefix)+1], func(t *testing.T) {
			called := false
			inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})

			server := newManagerHTTPTestServer(t, newAuthMiddleware(logger, tokens).Wrap(inner))
			defer server.Close()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
				server.URL+collectorIngestProcedure, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Authorization", managerBearer(token))

			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
			}
			if !called {
				t.Fatal("inner handler was not invoked on rotation token")
			}
		})
	}
}

// TestAuthMiddleware_MisconfiguredTokensFailsClosed pins the defensive
// behavior when the server is constructed without a token store. This
// should be unreachable in production (server.go always constructs one)
// but the middleware must refuse rather than panic.
func TestAuthMiddleware_MisconfiguredTokensFailsClosed(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler must not be invoked when tokens=nil")
	})

	server := newManagerHTTPTestServer(t, newAuthMiddleware(logger, nil).Wrap(inner))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		server.URL+collectorIngestProcedure, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", managerBearer(collectorTestSecret))

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("nil token store must not return OK, got %d", resp.StatusCode)
	}
}
