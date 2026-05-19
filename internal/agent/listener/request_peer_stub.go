//go:build !linux

package listener

import (
	"context"
	"net/http"
	"os"
)

type unixConnKey struct{}

// Shared tests replace this; the non-linux gate itself is a no-op.
var agentOwnerUID = os.Geteuid

// requireRequestPeerUIDMatchesAgentOwner is a no-op on non-linux dev builds.
func (l *Listener) requireRequestPeerUIDMatchesAgentOwner(w http.ResponseWriter, r *http.Request) bool {
	_ = l
	_ = w
	_ = r
	return true
}

// requestPeerPID returns 0 on non-linux dev builds. The agent only resolves
// rootPID for host_start on linux.
func requestPeerPID(ctx context.Context) (int32, error) {
	_ = ctx
	return 0, nil
}

// requestPeerUID returns 0 on non-linux dev builds.
func requestPeerUID(ctx context.Context) (uint32, error) {
	_ = ctx
	return 0, nil
}
