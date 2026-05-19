package managerclient_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
)

func TestNewConnectHTTPClient_DoesNotFollowRedirects(t *testing.T) {
	client := managerclient.NewConnectHTTPClient()
	if client == nil {
		t.Fatal("NewConnectHTTPClient: got nil")
	}
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect: got nil")
	}
	if err := client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect: got %v, want %v", err, http.ErrUseLastResponse)
	}
}

func TestConnectClientOptions_AddsBearerToken(t *testing.T) {
	svc := &fakeConfigService{
		handler: func(_ context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
			if got, want := req.Header().Get("Authorization"), "Bearer "+testManagerToken; got != want {
				t.Fatalf("authorization: got %q, want %q", got, want)
			}
			return connect.NewResponse(&managerv1.FetchConfigResponse{}), nil
		},
	}
	server := newFakeConfigServer(t, svc)
	defer server.Close()

	client := managerv1connect.NewConfigServiceClient(
		managerclient.NewConnectHTTPClient(),
		server.URL,
		managerclient.ConnectClientOptions(testManagerToken)...,
	)
	if _, err := client.FetchConfig(context.Background(), connect.NewRequest(&managerv1.FetchConfigRequest{})); err != nil {
		t.Fatalf("FetchConfig: %v", err)
	}
}
