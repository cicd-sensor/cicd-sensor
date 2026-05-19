//go:build linux

package listener

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"golang.org/x/sys/unix"
)

// unixConnKey lets request peer helpers read SO_PEERCRED.
type unixConnKey struct{}

// Tests replace this; production uses the agent process effective uid.
var agentOwnerUID = os.Geteuid

// requireRequestPeerUIDMatchesAgentOwner gates agent-helper endpoints, not Job authorization.
func (l *Listener) requireRequestPeerUIDMatchesAgentOwner(w http.ResponseWriter, r *http.Request) bool {
	uid, err := requestPeerUID(r.Context())
	if err != nil {
		l.logger.WarnContext(r.Context(), "peer_uid_unavailable", "error", err)
		l.writeError(w, r, http.StatusUnauthorized, "peer uid unavailable")
		return false
	}
	if uid != uint32(agentOwnerUID()) {
		l.writeError(w, r, http.StatusForbidden, "peer uid not authorized")
		return false
	}
	return true
}

// requestPeerPID reads the request peer's PID from SO_PEERCRED.
// Used to resolve the host_start root pid and to gate project-scope
// requests by membership in the Job's tracked PID set.
func requestPeerPID(ctx context.Context) (int32, error) {
	unixConn, err := unixConnFromContext(ctx)
	if err != nil {
		return 0, err
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("syscall conn: %w", err)
	}

	var pid int32
	var peerErr error
	if err := rawConn.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			peerErr = err
			return
		}
		pid = int32(ucred.Pid)
	}); err != nil {
		return 0, fmt.Errorf("control unix connection: %w", err)
	}
	if peerErr != nil {
		return 0, fmt.Errorf("get peer pid: %w", peerErr)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("invalid peer pid %d", pid)
	}
	return pid, nil
}

// requestPeerUID reads the request peer's UID from SO_PEERCRED.
// Used by agent-helper endpoints as an owner check, not Job authorization.
func requestPeerUID(ctx context.Context) (uint32, error) {
	unixConn, err := unixConnFromContext(ctx)
	if err != nil {
		return 0, err
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("syscall conn: %w", err)
	}

	var uid uint32
	var peerErr error
	if err := rawConn.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			peerErr = err
			return
		}
		uid = uint32(ucred.Uid)
	}); err != nil {
		return 0, fmt.Errorf("control unix connection: %w", err)
	}
	if peerErr != nil {
		return 0, fmt.Errorf("get peer uid: %w", peerErr)
	}
	return uid, nil
}

func unixConnFromContext(ctx context.Context) (*net.UnixConn, error) {
	connection, ok := ctx.Value(unixConnKey{}).(net.Conn)
	if !ok || connection == nil {
		return nil, errors.New("request is not backed by a unix connection")
	}

	unixConn, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, errors.New("request is not backed by a unix socket")
	}
	return unixConn, nil
}
