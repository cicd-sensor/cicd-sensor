package dockerd

import (
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerStartID(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, method, path, resource string
		want                         bool
	}{
		{"exec start is prepared", http.MethodPost, "/exec/" + id + "/start", "exec", true},
		{"versioned exec start is prepared", http.MethodPost, "/v1.47/exec/" + id + "/start", "exec", true},
		{"container start is separate from exec", http.MethodPost, "/containers/" + id + "/start", "exec", false},
		{"successful container start response has a preparation path", http.MethodPost, "/containers/" + id + "/start", "containers", true},
		{"exec inspect is not intercepted", http.MethodGet, "/exec/" + id + "/json", "exec", false},
		{"unresolved short ID falls back", http.MethodPost, "/exec/abc/start", "exec", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := dockerStartID(httptest.NewRequest(tc.method, tc.path, nil), tc.resource)
			if (got == id) != tc.want {
				t.Fatal(got)
			}
		})
	}
}

func TestHTTPPreparationUnavailablePassesRequest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusAccepted) }))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	h := withHTTPPreparation(httputil.NewSingleHostReverseProxy(target), filepath.Join(dir, "docker.sock"), filepath.Join(dir, "agent.sock"), jobcontext.ProviderGitLab, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/exec/"+strings.Repeat("a", 64)+"/start", nil))
	if !called || w.Code != http.StatusAccepted {
		t.Fatalf("proxy did not fail open: %d", w.Code)
	}
}

func TestPreparationPreservesResponseHook(t *testing.T) {
	for _, status := range []int{http.StatusCreated, http.StatusNoContent, http.StatusNotModified, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			called := false
			proxy := &httputil.ReverseProxy{ModifyResponse: func(resp *http.Response) error { called = true; return nil }}
			dir := t.TempDir()
			_ = withHTTPPreparation(proxy, filepath.Join(dir, "docker.sock"), filepath.Join(dir, "agent.sock"), jobcontext.ProviderGitLab, nil)
			resp := &http.Response{StatusCode: status, Request: httptest.NewRequest(http.MethodPost, "/containers/"+strings.Repeat("a", 64)+"/start", nil)}
			if err := proxy.ModifyResponse(resp); err != nil {
				t.Fatal(err)
			}
			if !called || resp.StatusCode != status {
				t.Fatal("existing response behavior changed")
			}
		})
	}
}
