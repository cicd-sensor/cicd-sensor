package dockerd

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecStartID(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, method, path string
		want               bool
	}{
		{"exec start is prepared", http.MethodPost, "/exec/" + id + "/start", true},
		{"versioned exec start is prepared", http.MethodPost, "/v1.47/exec/" + id + "/start", true},
		{"container start has no final-root guarantee", http.MethodPost, "/containers/" + id + "/start", false},
		{"exec inspect is not intercepted", http.MethodGet, "/exec/" + id + "/json", false},
		{"unresolved short ID falls back", http.MethodPost, "/exec/abc/start", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := execStartID(httptest.NewRequest(tc.method, tc.path, nil))
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
	h := withHTTPPreparation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusAccepted) }), filepath.Join(dir, "docker.sock"), filepath.Join(dir, "agent.sock"), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/exec/"+strings.Repeat("a", 64)+"/start", nil))
	if !called || w.Code != http.StatusAccepted {
		t.Fatalf("proxy did not fail open: %d", w.Code)
	}
}
