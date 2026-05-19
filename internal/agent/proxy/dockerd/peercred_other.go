//go:build !linux

package dockerd

import (
	"context"
	"net"
)

// connContext is a no-op on non-Linux platforms: SO_PEERCRED is Linux-only,
// and the proxy is only deployed on Linux runners. Keeping a stub keeps the
// package buildable on darwin so cmd/cicd-sensor tooling stays cross-platform.
func connContext(ctx context.Context, _ net.Conn) context.Context {
	return ctx
}
