package managerclient_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

const testManagerToken = managerauth.TokenPrefix + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func mustManagerClient(t *testing.T, baseURL string) *managerclient.ConfigClient {
	t.Helper()
	client, err := managerclient.NewConfigClient(testLogger, managerclient.Connection{
		BaseURL: baseURL,
		Token:   testManagerToken,
	})
	if err != nil {
		t.Fatalf("new manager client: %v", err)
	}
	return client
}

func mustRuleSources(t *testing.T, sets []rule.RuleSet, modifiers []rule.RuleModifier) []*managerv1.RuleSource {
	t.Helper()
	return protoconv.ToProtoRuleSources([]rulesource.LoadedRules{{
		RuleSets:      sets,
		RuleModifiers: modifiers,
	}})
}

type fakeConfigService struct {
	handler func(ctx context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error)
}

func (f *fakeConfigService) FetchConfig(ctx context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
	return f.handler(ctx, req)
}

func newFakeConfigServer(t *testing.T, svc *fakeConfigService) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := managerv1connect.NewConfigServiceHandler(svc)
	mux.Handle(path, handler)
	return newFakeHTTPServer(t, mux)
}

func newFakeHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("tcp listen is not permitted in this test environment: %v", err)
		}
		t.Fatalf("listen fake http server: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = ln
	server.Start()
	return server
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
