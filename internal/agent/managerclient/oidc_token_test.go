package managerclient_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/oauth2"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1/managerv1beta1connect"
)

func TestValidateIDTokenRequestURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		hosts   []string
		wantErr string
	}{
		{
			name: "allowlisted https host",
			raw:  "https://vstoken.actions.githubusercontent.com/_apis/oidc/oauth2/v2/token?api-version=2.0",
		},
		{
			name:    "http rejected",
			raw:     "http://vstoken.actions.githubusercontent.com/token",
			wantErr: "must use https",
		},
		{
			name:    "non-allowlisted host rejected",
			raw:     "https://169.254.169.254/latest/meta-data",
			wantErr: "not allowlisted",
		},
		{
			name:    "empty rejected",
			raw:     "",
			wantErr: "required",
		},
		{
			name:  "custom allowlist exact host",
			raw:   "https://oidc.ghes.example/token",
			hosts: []string{"oidc.ghes.example"},
		},
		{
			name:    "job cannot use host outside startup allowlist",
			raw:     "https://evil.example/token",
			hosts:   []string{"*.actions.githubusercontent.com"},
			wantErr: "not allowlisted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := managerclient.ValidateIDTokenRequestURL(tt.raw, tt.hosts)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateIDTokenRequestURL: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateIDTokenRequestURL: got %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestActionsIDTokenSource_GETMint(t *testing.T) {
	var gotMethod, gotAuth, gotAudience string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotAudience = r.URL.Query().Get("audience")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": mintJWT(t, time.Now().Add(5*time.Minute))})
	}))
	t.Cleanup(srv.Close)

	src := &managerclient.ActionsIDTokenSource{
		RequestURL:   srv.URL + "/token",
		RequestToken: "request-secret",
		Audience:     "https://manager.example.com",
		HTTPClient:   srv.Client(),
	}
	tok, err := src.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("method: got %q, want GET", gotMethod)
	}
	if gotAuth != "bearer request-secret" {
		t.Fatalf("auth: got %q", gotAuth)
	}
	if gotAudience != "https://manager.example.com" {
		t.Fatalf("audience: got %q", gotAudience)
	}
	if tok.AccessToken == "" {
		t.Fatal("empty access token")
	}
	if tok.Expiry.IsZero() {
		t.Fatal("expected JWT exp to populate token expiry")
	}
}

func TestActionsIDTokenSource_MintFailureUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	src := &managerclient.ActionsIDTokenSource{
		RequestURL:   srv.URL,
		RequestToken: "request-secret",
		Audience:     "https://manager.example.com",
		HTTPClient:   srv.Client(),
	}
	_, err := src.Token()
	if err == nil || !errors.Is(err, managerclient.ErrMintUnavailable) {
		t.Fatalf("Token: got %v, want ErrMintUnavailable", err)
	}
}

func TestReuseIDTokenSource_ConcurrentRefreshCollapsed(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"value": mintJWT(t, time.Now().Add(5*time.Minute)),
		})
	}))
	t.Cleanup(srv.Close)

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL:   srv.URL,
		RequestToken: "request-secret",
		Audience:     "https://manager.example.com",
		HTTPClient:   srv.Client(),
	}
	src := managerclient.NewReuseIDTokenSource(inner)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := src.Token()
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("mint calls: got %d, want 1 (concurrent refresh collapsed)", got)
	}
}

func TestCachedTokenSource_ForceRefreshForShutdownSummary(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"value": mintJWT(t, time.Now().Add(5*time.Minute)) + "-call-" + strconv.Itoa(int(n)),
		})
	}))
	t.Cleanup(srv.Close)

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL:   srv.URL,
		RequestToken: "request-secret",
		Audience:     "https://manager.example.com",
		HTTPClient:   srv.Client(),
	}
	cached := managerclient.NewCachedTokenSource(inner)

	if err := cached.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	tok1, err := cached.Token()
	if err != nil {
		t.Fatalf("Token after force: %v", err)
	}
	tok2, err := cached.Token()
	if err != nil {
		t.Fatalf("Token second: %v", err)
	}
	if tok1.AccessToken != tok2.AccessToken {
		t.Fatal("shutdown path must reuse forced JWT without reminting")
	}
	if calls.Load() != 1 {
		t.Fatalf("mint calls after force: got %d, want 1", calls.Load())
	}
}

func TestCachedTokenSource_ExpiryAfterForceRefreshRemints(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		exp := time.Now().Add(2 * time.Second)
		if n > 1 {
			exp = time.Now().Add(5 * time.Minute)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": mintJWT(t, exp) + "-n" + strconv.Itoa(int(n))})
	}))
	t.Cleanup(srv.Close)

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL: srv.URL, RequestToken: "secret", Audience: "https://manager.example.com",
		HTTPClient: srv.Client(),
	}
	cached := managerclient.NewCachedTokenSource(inner)
	if err := cached.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := cached.Token(); err != nil {
		t.Fatalf("Token after expiry: %v", err)
	}
	if calls.Load() < 2 {
		t.Fatalf("mint calls: got %d, want at least 2 after forced JWT expired", calls.Load())
	}
}

func TestCachedTokenSource_ForceRefreshFailureRetainsReuse(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(map[string]string{"value": mintJWT(t, time.Now().Add(5*time.Minute))})
			return
		}
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL: srv.URL, RequestToken: "secret", Audience: "https://manager.example.com",
		HTTPClient: srv.Client(),
	}
	cached := managerclient.NewCachedTokenSource(inner)
	if _, err := cached.Token(); err != nil {
		t.Fatalf("initial Token: %v", err)
	}
	if err := cached.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("ForceRefresh should retain reuse cache: %v", err)
	}
	tok, err := cached.Token()
	if err != nil {
		t.Fatalf("Token after failed force: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("expected cached JWT after failed force refresh")
	}
}

func TestCachedTokenSource_ForceRefreshAlwaysMints(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"value": mintJWT(t, time.Now().Add(5*time.Minute)) + "-n" + strconv.Itoa(int(n)),
		})
	}))
	t.Cleanup(srv.Close)

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL: srv.URL, RequestToken: "secret", Audience: "https://manager.example.com",
		HTTPClient: srv.Client(),
	}
	cached := managerclient.NewCachedTokenSource(inner)
	if _, err := cached.Token(); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if err := cached.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("mint calls: got %d, want 2 (force must not join cache-hit only)", got)
	}
}

func TestCachedTokenSource_MintStallTimesOut(t *testing.T) {
	const stall = 2 * time.Second
	const mintTimeout = 50 * time.Millisecond

	var startedOnce sync.Once
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedOnce.Do(func() { close(started) })
		// Stall past the mint deadline; exit when the mint context cancels so
		// Cleanup does not wait out the full stall.
		select {
		case <-r.Context().Done():
			return
		case <-time.After(stall):
			_ = json.NewEncoder(w).Encode(map[string]string{"value": mintJWT(t, time.Now().Add(5*time.Minute))})
		}
	}))
	t.Cleanup(srv.Close)

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL: srv.URL, RequestToken: "secret", Audience: "https://manager.example.com",
		// Transport without a short client.Timeout so the acquisition
		// context deadline is what fails (production sets both).
		HTTPClient: srv.Client(),
	}
	cached := managerclient.NewCachedTokenSourceWithTimeout(inner, mintTimeout)

	start := time.Now()
	_, err := cached.TokenContext(context.Background())
	elapsed := time.Since(start)

	if err == nil || !errors.Is(err, managerclient.ErrMintUnavailable) {
		t.Fatalf("TokenContext: got %v, want ErrMintUnavailable", err)
	}
	// Depending on cancel vs server close ordering, the transport may surface
	// deadline exceeded, context canceled, or EOF — all are mint failures
	// that aborted before the stall completed.
	if elapsed >= stall {
		t.Fatalf("acquisition waited %v, want fail near mint timeout %v (not full stall %v)", elapsed, mintTimeout, stall)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("acquisition took %v, want well under 500ms with injectable timeout", elapsed)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("mint handler never started")
	}
}

func TestCachedTokenSource_ConcurrentWaitersShareTimedOutMint(t *testing.T) {
	const mintTimeout = 80 * time.Millisecond
	var calls atomic.Int32
	releaseHandler := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-r.Context().Done():
			return
		case <-releaseHandler:
			_ = json.NewEncoder(w).Encode(map[string]string{"value": mintJWT(t, time.Now().Add(5*time.Minute))})
		case <-time.After(2 * time.Second):
			_ = json.NewEncoder(w).Encode(map[string]string{"value": mintJWT(t, time.Now().Add(5*time.Minute))})
		}
	}))
	t.Cleanup(func() {
		close(releaseHandler)
		srv.Close()
	})

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL: srv.URL, RequestToken: "secret", Audience: "https://manager.example.com",
		HTTPClient: srv.Client(),
	}
	cached := managerclient.NewCachedTokenSourceWithTimeout(inner, mintTimeout)

	const n = 6
	begin := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-begin
			_, err := cached.TokenContext(context.Background())
			errs <- err
		}()
	}
	ready.Wait()
	close(begin)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err == nil || !errors.Is(err, managerclient.ErrMintUnavailable) {
			t.Fatalf("TokenContext: got %v, want ErrMintUnavailable", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("mint calls: got %d, want 1 (concurrent waiters share one stalled acquisition)", got)
	}
}

func TestCachedTokenSource_CanceledWaiter(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(2 * time.Second)
		_ = json.NewEncoder(w).Encode(map[string]string{"value": mintJWT(t, time.Now().Add(5*time.Minute))})
	}))
	t.Cleanup(srv.Close)

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL: srv.URL, RequestToken: "secret", Audience: "https://manager.example.com",
		HTTPClient: srv.Client(),
	}
	cached := managerclient.NewCachedTokenSource(inner)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := cached.TokenContext(ctx)
		errCh <- err
	}()
	<-started
	cancel()
	err := <-errCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("TokenContext: got %v, want context.Canceled", err)
	}
}

func TestActionsIDTokenSource_RejectsRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "evil"})
	}))
	t.Cleanup(target.Close)

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	mintClient := managerclient.NewIDTokenMintHTTPClient()
	mintClient.Transport = redirect.Client().Transport
	src := &managerclient.ActionsIDTokenSource{
		RequestURL: redirect.URL, RequestToken: "secret", Audience: "https://manager.example.com",
		HTTPClient: mintClient,
	}
	_, err := src.Token()
	if err == nil || !errors.Is(err, managerclient.ErrMintUnavailable) {
		t.Fatalf("Token: got %v, want ErrMintUnavailable for redirect", err)
	}
}

func TestNewIDTokenMintHTTPClient_RejectsRedirect(t *testing.T) {
	client := managerclient.NewIDTokenMintHTTPClient()
	if client.Timeout != managerclient.DefaultMintHTTPTimeout {
		t.Fatalf("timeout: got %v, want %v", client.Timeout, managerclient.DefaultMintHTTPTimeout)
	}
	if err := client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect: got %v", err)
	}
}

func TestConnectClientOptions_TokenTypeHeaders(t *testing.T) {
	if managerclient.TokenTypeManagerToken != "manager-token" {
		t.Fatalf("manager-token value: got %q", managerclient.TokenTypeManagerToken)
	}
	if managerclient.TokenTypeIDToken != "id-token" {
		t.Fatalf("id-token value: got %q", managerclient.TokenTypeIDToken)
	}

	t.Run("manager-token", func(t *testing.T) {
		var gotAuth, gotType string
		svc := &fakeConfigService{
			handler: func(_ context.Context, req *connect.Request[managerv1beta1.FetchConfigRequest]) (*connect.Response[managerv1beta1.FetchConfigResponse], error) {
				gotAuth = req.Header().Get("Authorization")
				gotType = req.Header().Get(managerclient.TokenTypeHeader)
				return connect.NewResponse(&managerv1beta1.FetchConfigResponse{}), nil
			},
		}
		server := newFakeConfigServer(t, svc)
		t.Cleanup(server.Close)

		client := managerv1beta1connect.NewConfigServiceClient(
			managerclient.NewConnectHTTPClient(),
			server.URL,
			managerclient.ConnectClientOptions(testManagerToken)...,
		)
		if _, err := client.FetchConfig(context.Background(), connect.NewRequest(&managerv1beta1.FetchConfigRequest{})); err != nil {
			t.Fatalf("FetchConfig: %v", err)
		}
		if gotAuth != "Bearer "+testManagerToken {
			t.Fatalf("Authorization: got %q", gotAuth)
		}
		if gotType != managerclient.TokenTypeManagerToken {
			t.Fatalf("token type: got %q, want manager-token", gotType)
		}
	})

	t.Run("id-token", func(t *testing.T) {
		var gotAuth, gotType string
		svc := &fakeConfigService{
			handler: func(_ context.Context, req *connect.Request[managerv1beta1.FetchConfigRequest]) (*connect.Response[managerv1beta1.FetchConfigResponse], error) {
				gotAuth = req.Header().Get("Authorization")
				gotType = req.Header().Get(managerclient.TokenTypeHeader)
				return connect.NewResponse(&managerv1beta1.FetchConfigResponse{}), nil
			},
		}
		server := newFakeConfigServer(t, svc)
		t.Cleanup(server.Close)

		src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "eyJhbGciOiJSUzI1NiJ9.e30.sig"})
		client := managerv1beta1connect.NewConfigServiceClient(
			managerclient.NewConnectHTTPClient(),
			server.URL,
			managerclient.ConnectClientOptionsWithAuth(managerclient.IDTokenAuth(src))...,
		)
		if _, err := client.FetchConfig(context.Background(), connect.NewRequest(&managerv1beta1.FetchConfigRequest{})); err != nil {
			t.Fatalf("FetchConfig: %v", err)
		}
		if gotAuth != "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig" {
			t.Fatalf("Authorization: got %q", gotAuth)
		}
		if gotType != managerclient.TokenTypeIDToken {
			t.Fatalf("token type: got %q, want id-token", gotType)
		}
	})

	t.Run("mint failure maps to Unavailable", func(t *testing.T) {
		failing := tokenErrSource{err: managerclient.ErrMintUnavailable}
		client := managerv1beta1connect.NewConfigServiceClient(
			managerclient.NewConnectHTTPClient(),
			"http://127.0.0.1:1",
			managerclient.ConnectClientOptionsWithAuth(managerclient.IDTokenAuth(failing))...,
		)
		_, err := client.FetchConfig(context.Background(), connect.NewRequest(&managerv1beta1.FetchConfigRequest{}))
		if err == nil {
			t.Fatal("expected error")
		}
		var connectErr *connect.Error
		if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeUnavailable {
			t.Fatalf("error: got %v, want Unavailable", err)
		}
	})
}

type tokenErrSource struct{ err error }

func (s tokenErrSource) Token() (*oauth2.Token, error) { return nil, s.err }

func mintJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return header + "." + payload + ".sig"
}
