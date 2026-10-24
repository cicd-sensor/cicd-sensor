package listener_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/listener"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestListener_ProjectStart_OIDCManagerPath(t *testing.T) {
	key := mustOIDCRSAKey(t)
	var mintCalls atomic.Int32
	var gotAuth, gotType string

	mintSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mintCalls.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("mint method: got %s, want GET", r.Method)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "bearer ") {
			t.Errorf("mint Authorization missing bearer")
		}
		if got := r.URL.Query().Get("audience"); got != "https://manager.example.com" {
			t.Errorf("audience: got %q", got)
		}
		raw := mustSignOIDCTestJWT(t, key, "acme/example", "acme", time.Now().Add(5*time.Minute))
		_ = json.NewEncoder(w).Encode(map[string]string{"value": raw})
	}))
	t.Cleanup(mintSrv.Close)

	cfgSvc := &fakeConfigService{
		handler: func(_ context.Context, req *connect.Request[managerv1beta1.FetchConfigRequest]) (*connect.Response[managerv1beta1.FetchConfigResponse], error) {
			gotAuth = req.Header().Get("Authorization")
			gotType = req.Header().Get(managerclient.TokenTypeHeader)
			return connect.NewResponse(&managerv1beta1.FetchConfigResponse{
				Config: &managerv1beta1.ServedConfig{
					ConfigRevision: "oidc-rev",
				},
			}), nil
		},
	}
	managerSrv := newFakeConfigServer(t, cfgSvc)
	t.Cleanup(managerSrv.Close)

	mintHost := mustOIDCURLHost(t, mintSrv.URL)
	client, registry, cleanup := setupOIDCListener(t, []string{mintHost}, mintSrv.Client())
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "99",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "oidc-tracking",
		"manager_url":               managerSrv.URL,
		"manager_auth":              "oidc",
		"id_token_request_url":      mintSrv.URL + "/token",
		"id_token_request_token":    "request-secret",
		"id_token_audience":         "https://manager.example.com",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("project/start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("project/start status=%d body=%s", resp.StatusCode, payload)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "99", "build", "1", "oidc-tracking")
	if listenerRegisteredJob(registry, id) == nil {
		t.Fatal("expected job registered")
	}
	if mintCalls.Load() < 1 {
		t.Fatal("expected mint during FetchConfig")
	}
	if gotType != managerclient.TokenTypeIDToken {
		t.Fatalf("token type: got %q, want id-token", gotType)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") || strings.Count(gotAuth, ".") != 2 {
		t.Fatalf("Authorization: got %q, want Bearer JWT", gotAuth)
	}
}

func TestListener_ProjectStart_OIDCRejectsNonAllowlistedHost(t *testing.T) {
	mintSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "unused"})
	}))
	t.Cleanup(mintSrv.Close)

	client, _, cleanup := setupOIDCListener(t, []string{"*.actions.githubusercontent.com"}, mintSrv.Client())
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "100",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "oidc-bad-host",
		"manager_url":               "https://manager.example.com",
		"manager_auth":              "oidc",
		"id_token_request_url":      mintSrv.URL + "/token",
		"id_token_request_token":    "request-secret",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("project/start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s, want 400 for non-allowlisted host", resp.StatusCode, payload)
	}
}

func setupOIDCListener(t *testing.T, hosts []string, mintClient *http.Client) (*http.Client, *jobregistry.JobRegistry, func()) {
	t.Helper()
	dir := newTestSocketDir(t, "cicd-sensor-oidc-")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "t.sock")

	jobRegistry := jobregistry.New(testLogger)
	jobRegistry.SetBaselineLoadForTesting(func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		return rulesource.LoadedRules{}, nil
	})
	l := listener.New(listener.Config{
		Logger:                 testLogger,
		JobRegistry:            jobRegistry,
		SocketPath:             sock,
		RunnerType:             "machine",
		Provider:               jobcontext.ProviderGitHub,
		IDTokenRequestURLHosts: hosts,
		IDTokenHTTPClient:      mintClient,
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- l.Serve(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case err := <-errCh:
			t.Fatalf("listener failed to start: %v", err)
		case <-deadline:
			t.Fatal("socket did not appear within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}
	cleanup := func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
		}
	}
	return client, jobRegistry, cleanup
}

func mustOIDCURLHost(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return parsed.Hostname()
}

func mustOIDCRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func mustSignOIDCTestJWT(t *testing.T, key *rsa.PrivateKey, repository, owner string, exp time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":              "https://token.actions.githubusercontent.com",
		"aud":              []string{"https://manager.example.com"},
		"exp":              exp.Unix(),
		"iat":              time.Now().Add(-time.Minute).Unix(),
		"sub":              "repo:" + repository + ":ref:refs/heads/main",
		"repository":       repository,
		"repository_owner": owner,
	})
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}
