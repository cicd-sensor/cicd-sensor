package managerclient_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/oauth2"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1/managerv1beta1connect"
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
		handler: func(_ context.Context, req *connect.Request[managerv1beta1.FetchConfigRequest]) (*connect.Response[managerv1beta1.FetchConfigResponse], error) {
			if got, want := req.Header().Get("Authorization"), "Bearer "+testManagerToken; got != want {
				t.Fatalf("authorization: got %q, want %q", got, want)
			}
			if got, want := req.Header().Get(managerclient.TokenTypeHeader), managerclient.TokenTypeManagerToken; got != want {
				t.Fatalf("token type: got %q, want %q", got, want)
			}
			return connect.NewResponse(&managerv1beta1.FetchConfigResponse{}), nil
		},
	}
	server := newFakeConfigServer(t, svc)
	defer server.Close()

	client := managerv1beta1connect.NewConfigServiceClient(
		managerclient.NewConnectHTTPClient(),
		server.URL,
		managerclient.ConnectClientOptions(testManagerToken)...,
	)
	if _, err := client.FetchConfig(context.Background(), connect.NewRequest(&managerv1beta1.FetchConfigRequest{})); err != nil {
		t.Fatalf("FetchConfig: %v", err)
	}
}

func TestConnectClientOptions_CanceledTokenAcquisition(t *testing.T) {
	slow := slowTokenSource{delay: 2 * time.Second}
	client := managerv1beta1connect.NewConfigServiceClient(
		managerclient.NewConnectHTTPClient(),
		"http://127.0.0.1:1",
		managerclient.ConnectClientOptionsWithAuth(managerclient.IDTokenAuth(slow))...,
	)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := client.FetchConfig(ctx, connect.NewRequest(&managerv1beta1.FetchConfigRequest{}))
	if err == nil {
		t.Fatal("expected error")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeCanceled {
		t.Fatalf("error: got %v, want Canceled", err)
	}
}

type slowTokenSource struct{ delay time.Duration }

func (s slowTokenSource) Token() (*oauth2.Token, error) {
	time.Sleep(s.delay)
	return &oauth2.Token{AccessToken: "tok"}, nil
}

func (s slowTokenSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	select {
	case <-time.After(s.delay):
		return &oauth2.Token{AccessToken: "tok"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
