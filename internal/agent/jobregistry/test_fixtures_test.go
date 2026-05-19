package jobregistry_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"connectrpc.com/connect"

	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

const fakeConfigServerAddr = "127.0.0.1:0"

type fakeConfigService struct {
	handler func(ctx context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error)
}

func (f *fakeConfigService) FetchConfig(ctx context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
	return f.handler(ctx, req)
}

func newFakeConfigServer(t *testing.T, addr string, svc *fakeConfigService) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := managerv1connect.NewConfigServiceHandler(svc)
	mux.Handle(path, handler)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("tcp listen on %s is not permitted in this test environment: %v", addr, err)
		}
		t.Fatalf("listen fake config server on %s: %v", addr, err)
	}
	server := httptest.NewUnstartedServer(mux)
	server.Listener = ln
	server.Start()
	return server
}

func mustRuleSources(t *testing.T, sets []rule.RuleSet, modifiers []rule.RuleModifier) []*managerv1.RuleSource {
	t.Helper()
	return protoconv.ToProtoRuleSources([]rulesource.LoadedRules{{
		RuleSets:      sets,
		RuleModifiers: modifiers,
	}})
}
