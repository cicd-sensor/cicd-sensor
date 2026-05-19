package manager

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
)

func TestUnaryOnlyInterceptor_AllowsUnary(t *testing.T) {
	called := false
	next := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		return nil, nil
	}

	_, err := unaryOnlyInterceptor{}.WrapUnary(next)(context.Background(), nil)
	if err != nil {
		t.Fatalf("unary returned error: %v", err)
	}
	if !called {
		t.Fatal("unary handler was not called")
	}
}

func TestUnaryOnlyInterceptor_RejectsStreamingHandler(t *testing.T) {
	called := false
	next := func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		called = true
		return nil
	}

	err := unaryOnlyInterceptor{}.WrapStreamingHandler(next)(context.Background(), stubStreamingHandlerConn{})
	if got := connect.CodeOf(err); got != connect.CodeUnimplemented {
		t.Fatalf("code: got %v, want %v (err=%v)", got, connect.CodeUnimplemented, err)
	}
	if !strings.Contains(err.Error(), "unaryOnlyInterceptor") {
		t.Fatalf("err message: got %q, want to contain %q", err.Error(), "unaryOnlyInterceptor")
	}
	if !strings.Contains(err.Error(), testStreamingProcedure) {
		t.Fatalf("err message: got %q, want to contain procedure %q", err.Error(), testStreamingProcedure)
	}
	if called {
		t.Fatal("streaming handler was called")
	}
}

const testStreamingProcedure = "/cicd_sensor.manager.v1.TestService/Stream"

type stubStreamingHandlerConn struct{}

func (stubStreamingHandlerConn) Spec() connect.Spec {
	return connect.Spec{Procedure: testStreamingProcedure}
}

func (stubStreamingHandlerConn) Peer() connect.Peer { return connect.Peer{} }

func (stubStreamingHandlerConn) Receive(any) error { return nil }

func (stubStreamingHandlerConn) RequestHeader() http.Header { return http.Header{} }

func (stubStreamingHandlerConn) Send(any) error { return nil }

func (stubStreamingHandlerConn) ResponseHeader() http.Header { return http.Header{} }

func (stubStreamingHandlerConn) ResponseTrailer() http.Header { return http.Header{} }
