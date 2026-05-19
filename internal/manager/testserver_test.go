package manager

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func newManagerHTTPTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("tcp listen is not permitted in this test environment: %v", err)
		}
		t.Fatalf("listen test server: %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.Listener = ln
	server.Start()
	return server
}

func managerBearer(token string) string {
	return "Bearer " + token
}
