package manager

import (
	"context"
	"errors"

	"connectrpc.com/connect"
)

// unaryOnlyInterceptor rejects streaming handlers even if one is accidentally
// registered later. The proto and generated code are already unary-only; this
// is the final runtime guard.
type unaryOnlyInterceptor struct{}

var _ connect.Interceptor = unaryOnlyInterceptor{}

func (unaryOnlyInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return next
}

func (unaryOnlyInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (unaryOnlyInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(_ context.Context, conn connect.StreamingHandlerConn) error {
		return connect.NewError(connect.CodeUnimplemented, errors.New("streaming RPCs are not supported on this server (unaryOnlyInterceptor): "+conn.Spec().Procedure))
	}
}
