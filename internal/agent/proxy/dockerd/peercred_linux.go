//go:build linux

package dockerd

import (
	"context"
	"net"

	"golang.org/x/sys/unix"
)

// connContext attaches the connecting docker client's PID to every
// http.Request derived from this connection. SO_PEERCRED only works on
// unix sockets; non-unix conns get the zero pid.
func connContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var pid int32
	_ = raw.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return
		}
		pid = int32(ucred.Pid)
	})
	if pid <= 0 {
		return ctx
	}
	return context.WithValue(ctx, peerPIDCtxKey{}, pid)
}
