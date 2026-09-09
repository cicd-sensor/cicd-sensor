//go:build linux

package httpprepare

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The node-only packet protocol carries FDs with byte 0; replies are 0 (done)
// or 1 (incomplete). Lifecycle source labels stay in the producer log.
func prepareRemote(ctx context.Context, socket string, resolve RootResolver) error {
	var dialer net.Dialer
	c, err := dialer.DialContext(ctx, "unixpacket", socket)
	if err != nil {
		return err
	}
	defer c.Close()
	conn := c.(*net.UnixConn)
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	// Dial first: unavailable preparation does not inspect the runtime or root.
	root, err := resolve(ctx)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	files, scanErr := OpenFiles(ctx, root)
	defer CloseFiles(files)
	if err = ctx.Err(); err != nil {
		return err
	}
	if len(files) == 0 {
		return scanErr
	}
	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd())
	}
	n, _, err := conn.WriteMsgUnix([]byte{0}, unix.UnixRights(fds...), nil)
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("short HTTP preparation message")
	}
	var response [1]byte
	n, _, flags, _, err := conn.ReadMsgUnix(response[:], nil)
	if err != nil {
		return err
	}
	if n != 1 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || response[0] > 1 {
		return errors.New("invalid HTTP preparation reply")
	}
	if response[0] != 0 {
		return errors.New("HTTP target preparation incomplete")
	}
	return scanErr
}

// Serve receives exact FDs only from the Agent owner. This socket must stay on
// the node; it is never part of the runner/job socket mount or route family.
func Serve(ctx context.Context, socket string, handler FileHandler, logger *slog.Logger) error {
	if handler == nil {
		return errors.New("HTTP preparation handler required")
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("HTTP preparation path is not a socket")
		}
		c, e := net.DialTimeout("unixpacket", socket, 50*time.Millisecond)
		if e == nil {
			_ = c.Close()
			return errors.New("HTTP preparation socket already active")
		}
		if !errors.Is(e, unix.ECONNREFUSED) && !errors.Is(e, os.ErrNotExist) {
			return fmt.Errorf("HTTP preparation socket status uncertain: %w", e)
		}
		if e = os.Remove(socket); e != nil {
			return e
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socket, Net: "unixpacket"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0o600); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, MaxConcurrent)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		wg.Go(func() {
			defer func() {
				<-slots
				_ = conn.Close()
			}()
			if err := serveConnection(ctx, conn, handler); err != nil && logger != nil {
				logger.DebugContext(ctx, "http_preparation_request_failed", "error", err)
			}
		})
	}
}

func serveConnection(ctx context.Context, conn *net.UnixConn, handler FileHandler) error {
	accepted := time.Now()
	if err := conn.SetDeadline(accepted.Add(Budget)); err != nil {
		return err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var credential *unix.Ucred
	var socketErr error
	if err = raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if socketErr != nil {
		return socketErr
	}
	if credential == nil || credential.Uid != uint32(os.Geteuid()) {
		return errors.New("HTTP preparation peer UID mismatch")
	}
	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(MaxFiles*4))
	// On Linux ReadMsgUnix receives all descriptors with atomic CLOEXEC.
	n, oobn, flags, _, err := conn.ReadMsgUnix(data, oob)
	if err != nil {
		return err
	}
	files, err := receivedFiles(oob[:oobn])
	defer func() { CloseFiles(files) }()
	if err != nil {
		return err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return errors.New("truncated HTTP preparation message")
	}
	if n != 1 || data[0] != 0 || len(files) == 0 || len(files) > MaxFiles {
		return errors.New("invalid HTTP preparation packet")
	}
	requestCtx, cancel := context.WithDeadline(ctx, accepted.Add(Budget))
	defer cancel()
	if err = requestCtx.Err(); err != nil {
		return err
	}
	owned := files
	files = nil // handler adopts descriptors even on timeout/rejection
	prepareErr := handler(requestCtx, owned, "remote")
	reply := byte(0)
	if prepareErr != nil {
		reply = 1
	}
	_, err = conn.Write([]byte{reply})
	return err
}

func receivedFiles(oob []byte) (files []*os.File, err error) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			continue
		}
		fds, e := unix.ParseUnixRights(&message)
		if e != nil {
			return files, e
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "HTTP preparation target"))
		}
	}
	return files, nil
}
