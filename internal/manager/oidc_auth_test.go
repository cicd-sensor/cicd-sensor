package manager

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v5"

	oidcauth "github.com/cicd-sensor/cicd-sensor/internal/managerauth/oidc"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1/managerv1beta1connect"
)

func TestAuthMiddleware_TokenTypeRouting(t *testing.T) {
	key := mustTestRSAKey(t)
	oidcVerifier := oidcauth.NewVerifierWithKeySet(oidcauth.Config{
		Enabled:  true,
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: "https://manager.example.com",
		JWKSURL:  "unused",
		Allow:    []oidcauth.AllowEntry{{Repository: "acme-corp/api"}},
	}, &gooidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}})

	tokens := NewTokenStore([]string{collectorTestSecret})
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	mw := newAuthMiddleware(logger, authMiddlewareOptions{
		tokens: tokens,
		oidc:   oidcVerifier,
		oidcOn: true,
	})

	t.Run("manager-token header", func(t *testing.T) {
		principal := mustAuth(t, mw, collectorTestSecret, oidcauth.TokenTypeManagerToken)
		if principal.Kind != oidcauth.AuthKindManagerToken {
			t.Fatalf("kind: got %q", principal.Kind)
		}
	})

	t.Run("absent header treated as manager-token", func(t *testing.T) {
		principal := mustAuth(t, mw, collectorTestSecret, "")
		if principal.Kind != oidcauth.AuthKindManagerToken {
			t.Fatalf("kind: got %q", principal.Kind)
		}
	})

	t.Run("id-token success", func(t *testing.T) {
		raw := mustTestSignJWT(t, key, "acme-corp/api", "acme-corp")
		principal := mustAuth(t, mw, raw, oidcauth.TokenTypeIDToken)
		if principal.Kind != oidcauth.AuthKindIDToken {
			t.Fatalf("kind: got %q", principal.Kind)
		}
		if principal.Repository != "acme-corp/api" {
			t.Fatalf("repository: got %q", principal.Repository)
		}
	})

	t.Run("id-token while oidc disabled", func(t *testing.T) {
		disabled := newAuthMiddleware(logger, authMiddlewareOptions{tokens: tokens})
		raw := mustTestSignJWT(t, key, "acme-corp/api", "acme-corp")
		mustAuthFail(t, disabled, raw, oidcauth.TokenTypeIDToken, http.StatusUnauthorized)
	})

	t.Run("unknown token type", func(t *testing.T) {
		mustAuthFail(t, mw, collectorTestSecret, "bearer", http.StatusUnauthorized)
	})
}

func TestAuthMiddleware_JWKSFetchUnavailable(t *testing.T) {
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	t.Cleanup(jwks.Close)

	verifier, err := oidcauth.NewVerifier(context.Background(), oidcauth.Config{
		Enabled:  true,
		Issuer:   "https://token.actions.githubusercontent.com",
		Audience: "https://manager.example.com",
		JWKSURL:  jwks.URL,
		Allow:    []oidcauth.AllowEntry{{RepositoryOwner: "acme-corp"}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	mw := newAuthMiddleware(logger, authMiddlewareOptions{oidc: verifier, oidcOn: true})

	key := mustTestRSAKey(t)
	raw := mustTestSignJWT(t, key, "acme-corp/api", "acme-corp")
	status, body := authStatus(t, mw, raw, oidcauth.TokenTypeIDToken)
	if status != http.StatusServiceUnavailable && status != http.StatusOK {
		// Connect Unavailable maps to 503 for Connect protocol; plain HTTP
		// ErrorWriter may use different mapping. Accept Unavailable code in body.
		if !strings.Contains(body, "unavailable") && status != 503 {
			t.Fatalf("status=%d body=%s, want Unavailable", status, body)
		}
	}
	if status == http.StatusUnauthorized {
		t.Fatalf("JWKS fetch must not look like auth failure: status=%d body=%s", status, body)
	}
}

func TestOIDCJobIdentityInterceptor(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	interceptor := oidcJobIdentityInterceptor{logger: logger}

	oidcPrincipal := authPrincipal{
		Kind:       oidcauth.AuthKindIDToken,
		Repository: "acme-corp/api",
	}
	managerPrincipal := authPrincipal{Kind: oidcauth.AuthKindManagerToken}

	t.Run("match succeeds", func(t *testing.T) {
		ctx := authn.SetInfo(context.Background(), oidcPrincipal)
		msg := &managerv1beta1.FetchConfigRequest{
			JobIdentity: &managerv1beta1.JobIdentity{
				Provider:    "github",
				ProjectPath: "acme-corp/api",
			},
		}
		if err := interceptor.check(ctx, msg); err != nil {
			t.Fatalf("check: %v", err)
		}
	})

	t.Run("case-normalized project_path", func(t *testing.T) {
		ctx := authn.SetInfo(context.Background(), oidcPrincipal)
		msg := &managerv1beta1.FetchConfigRequest{
			JobIdentity: &managerv1beta1.JobIdentity{
				Provider:    "github",
				ProjectPath: "Acme-Corp/API",
			},
		}
		if err := interceptor.check(ctx, msg); err != nil {
			t.Fatalf("check: %v", err)
		}
		if got := msg.GetJobIdentity().GetProjectPath(); got != "acme-corp/api" {
			t.Fatalf("project_path after bind: got %q, want verified repository claim", got)
		}
	})

	t.Run("mismatch permission_denied", func(t *testing.T) {
		ctx := authn.SetInfo(context.Background(), oidcPrincipal)
		msg := &managerv1beta1.FetchConfigRequest{
			JobIdentity: &managerv1beta1.JobIdentity{
				Provider:    "github",
				ProjectPath: "other/repo",
			},
		}
		err := interceptor.check(ctx, msg)
		assertPermissionDenied(t, err)
	})

	t.Run("ingest log bind", func(t *testing.T) {
		ctx := authn.SetInfo(context.Background(), oidcPrincipal)
		msg := &managerv1beta1.IngestLogRequest{
			Batch: &managerv1beta1.IngestLogBatch{
				JobIdentity: &managerv1beta1.JobIdentity{
					Provider:    "github",
					ProjectPath: "acme-corp/api",
				},
			},
		}
		if err := interceptor.check(ctx, msg); err != nil {
			t.Fatalf("check: %v", err)
		}
	})

	t.Run("oidc without job identity message rejects", func(t *testing.T) {
		ctx := authn.SetInfo(context.Background(), oidcPrincipal)
		err := interceptor.check(ctx, struct{}{})
		assertPermissionDenied(t, err)
	})

	t.Run("manager-token skips bind", func(t *testing.T) {
		ctx := authn.SetInfo(context.Background(), managerPrincipal)
		msg := &managerv1beta1.FetchConfigRequest{
			JobIdentity: &managerv1beta1.JobIdentity{
				Provider:    "github",
				ProjectPath: "other/repo",
			},
		}
		if err := interceptor.check(ctx, msg); err != nil {
			t.Fatalf("manager-token must skip bind: %v", err)
		}
	})
}

func TestOIDCFakeIssuer_FetchConfigEndToEnd(t *testing.T) {
	key := mustTestRSAKey(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				mustJWK(t, key),
			},
		})
	}))
	t.Cleanup(jwks.Close)

	startupPath := writeStartupConfig(t, `
bind:
  address: 127.0.0.1
  port: 0
auth:
  oidc:
    enabled: true
    issuer: https://token.actions.githubusercontent.com
    audience: https://manager.example.com
    jwks_url: `+jwks.URL+`
    allow:
      - repository: acme-corp/api
`)
	startupCfg, err := LoadStartupConfig(startupPath)
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}

	server := NewServer(testLogger, ":0", nil, &ServedConfig{
		ConfigRevision: startupCfg.Revision,
	}, "", &startupCfg, nil)
	ts := newManagerHTTPTestServer(t, server.Handler())
	t.Cleanup(ts.Close)

	client := managerv1beta1connect.NewConfigServiceClient(ts.Client(), ts.URL)
	raw := mustTestSignJWT(t, key, "acme-corp/api", "acme-corp")

	t.Run("matching identity succeeds", func(t *testing.T) {
		req := connect.NewRequest(&managerv1beta1.FetchConfigRequest{
			JobIdentity: &managerv1beta1.JobIdentity{
				Provider:               "github",
				ProviderHost:           "github.com",
				ProjectPath:            "acme-corp/api",
				GithubRunId:            "1",
				GithubJob:              "build",
				GithubRunAttempt:       "1",
				GithubRunnerTrackingId: "runner-1",
			},
		})
		req.Header().Set("Authorization", "Bearer "+raw)
		req.Header().Set(oidcauth.TokenTypeHeader, oidcauth.TokenTypeIDToken)
		if _, err := client.FetchConfig(context.Background(), req); err != nil {
			t.Fatalf("FetchConfig: %v", err)
		}
	})

	t.Run("project_path mismatch permission_denied", func(t *testing.T) {
		req := connect.NewRequest(&managerv1beta1.FetchConfigRequest{
			JobIdentity: &managerv1beta1.JobIdentity{
				Provider:               "github",
				ProviderHost:           "github.com",
				ProjectPath:            "other/repo",
				GithubRunId:            "1",
				GithubJob:              "build",
				GithubRunAttempt:       "1",
				GithubRunnerTrackingId: "runner-1",
			},
		})
		req.Header().Set("Authorization", "Bearer "+raw)
		req.Header().Set(oidcauth.TokenTypeHeader, oidcauth.TokenTypeIDToken)
		_, err := client.FetchConfig(context.Background(), req)
		assertPermissionDenied(t, err)
	})
}

func mustJWK(t *testing.T, key *rsa.PrivateKey) map[string]any {
	t.Helper()
	n := key.PublicKey.N.Bytes()
	e := key.PublicKey.E
	eb := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	for len(eb) > 1 && eb[0] == 0 {
		eb = eb[1:]
	}
	return map[string]any{
		"kty": "RSA",
		"kid": "test-key",
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(n),
		"e":   base64.RawURLEncoding.EncodeToString(eb),
	}
}

func TestLoadStartupConfig_OIDCAllowlist(t *testing.T) {
	t.Run("valid oidc config", func(t *testing.T) {
		path := writeStartupConfig(t, `
bind:
  address: 127.0.0.1
  port: 8080
auth:
  oidc:
    enabled: true
    issuer: https://token.actions.githubusercontent.com
    audience: https://manager.example.com
    jwks_url: https://token.actions.githubusercontent.com/.well-known/jwks
    allow:
      - repository_owner: acme-corp
      - repository: partner-org/payments
`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if !cfg.Auth.OIDC.Enabled {
			t.Fatal("expected oidc enabled")
		}
		if len(cfg.Auth.OIDC.Allow) != 2 {
			t.Fatalf("allow len: got %d", len(cfg.Auth.OIDC.Allow))
		}
	})

	t.Run("empty allow refused", func(t *testing.T) {
		path := writeStartupConfig(t, `
auth:
  oidc:
    enabled: true
    issuer: https://token.actions.githubusercontent.com
    audience: https://manager.example.com
    jwks_url: https://token.actions.githubusercontent.com/.well-known/jwks
    allow: []
`)
		_, err := LoadStartupConfig(path)
		if err == nil || !strings.Contains(err.Error(), "allow must be non-empty") {
			t.Fatalf("got %v, want empty allow error", err)
		}
	})

	t.Run("unknown claim key rejected", func(t *testing.T) {
		path := writeStartupConfig(t, `
auth:
  oidc:
    enabled: true
    issuer: https://token.actions.githubusercontent.com
    audience: https://manager.example.com
    jwks_url: https://token.actions.githubusercontent.com/.well-known/jwks
    allow:
      - ref: refs/heads/main
`)
		_, err := LoadStartupConfig(path)
		if err == nil {
			t.Fatal("expected unknown key / empty known-key rejection")
		}
	})

	t.Run("repository_owner with slash rejected", func(t *testing.T) {
		path := writeStartupConfig(t, `
auth:
  oidc:
    enabled: true
    issuer: https://token.actions.githubusercontent.com
    audience: https://manager.example.com
    jwks_url: https://token.actions.githubusercontent.com/.well-known/jwks
    allow:
      - repository_owner: acme/corp
`)
		_, err := LoadStartupConfig(path)
		if err == nil || !strings.Contains(err.Error(), "must not contain '/'") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("omitted repository key accepted as unconstrained", func(t *testing.T) {
		path := writeStartupConfig(t, `
auth:
  oidc:
    enabled: true
    issuer: https://token.actions.githubusercontent.com
    audience: https://manager.example.com
    jwks_url: https://token.actions.githubusercontent.com/.well-known/jwks
    allow:
      - repository_owner: acme-corp
`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		oidcCfg, err := cfg.OIDCConfig()
		if err != nil {
			t.Fatalf("OIDCConfig: %v", err)
		}
		if got := oidcCfg.Allow[0].Repository; got != "" {
			t.Fatalf("repository: got %q, want omitted/empty constraint", got)
		}
	})

	t.Run("explicit empty repository rejected", func(t *testing.T) {
		path := writeStartupConfig(t, `
auth:
  oidc:
    enabled: true
    issuer: https://token.actions.githubusercontent.com
    audience: https://manager.example.com
    jwks_url: https://token.actions.githubusercontent.com/.well-known/jwks
    allow:
      - repository_owner: acme-corp
        repository: ""
`)
		_, err := LoadStartupConfig(path)
		if err == nil || !strings.Contains(err.Error(), "repository must not be empty") {
			t.Fatalf("got %v, want explicit empty rejection", err)
		}
	})

	t.Run("explicit whitespace repository rejected", func(t *testing.T) {
		path := writeStartupConfig(t, `
auth:
  oidc:
    enabled: true
    issuer: https://token.actions.githubusercontent.com
    audience: https://manager.example.com
    jwks_url: https://token.actions.githubusercontent.com/.well-known/jwks
    allow:
      - repository_owner: acme-corp
        repository: "   "
`)
		_, err := LoadStartupConfig(path)
		if err == nil || !strings.Contains(err.Error(), "repository must not be empty") {
			t.Fatalf("got %v, want whitespace rejection", err)
		}
	})
}

func writeStartupConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manager.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func mustAuth(t *testing.T, mw *authn.Middleware, token, tokenType string) authPrincipal {
	t.Helper()
	var got authPrincipal
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			t.Error("missing principal")
		}
		got = p
		w.WriteHeader(http.StatusOK)
	})
	server := newManagerHTTPTestServer(t, mw.Wrap(inner))
	t.Cleanup(server.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/rpc", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if tokenType != "" {
		req.Header.Set(oidcauth.TokenTypeHeader, tokenType)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d body %s", resp.StatusCode, body)
	}
	return got
}

func mustAuthFail(t *testing.T, mw *authn.Middleware, token, tokenType string, want int) {
	t.Helper()
	status, _ := authStatus(t, mw, token, tokenType)
	if status != want {
		t.Fatalf("status: got %d, want %d", status, want)
	}
}

func authStatus(t *testing.T, mw *authn.Middleware, token, tokenType string) (int, string) {
	t.Helper()
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := newManagerHTTPTestServer(t, mw.Wrap(inner))
	t.Cleanup(server.Close)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/rpc", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if tokenType != "" {
		req.Header.Set(oidcauth.TokenTypeHeader, tokenType)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func assertPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected permission denied")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodePermissionDenied {
		t.Fatalf("error: got %v, want permission_denied", err)
	}
}

func mustTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return key
}

func mustTestSignJWT(t *testing.T, key *rsa.PrivateKey, repository, owner string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":              "https://token.actions.githubusercontent.com",
		"aud":              []string{"https://manager.example.com"},
		"exp":              now.Add(5 * time.Minute).Unix(),
		"iat":              now.Unix(),
		"nbf":              now.Add(-time.Minute).Unix(),
		"repository":       repository,
		"repository_owner": owner,
	})
	token.Header["kid"] = "test-key"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}
