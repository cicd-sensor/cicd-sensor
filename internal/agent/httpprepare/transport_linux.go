//go:build linux

package httpprepare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"golang.org/x/sys/unix"
)

const maxMessageBytes = 1024

type preparationMessage struct {
	Source   string
	Deadline int64
	Files    int
}

type preparationResponse struct {
	Result kernelio.HTTPPreparationResult
	Error  string
}

func prepareRemote(ctx context.Context, socket string, resolve RootResolver, source string) error {
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
	root, extra, err := resolve(ctx)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	files, _, scanErr := OpenFiles(ctx, root, extra)
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
	data, err := json.Marshal(preparationMessage{Source: source, Deadline: deadline.UnixNano(), Files: len(files)})
	if err != nil {
		return err
	}
	n, _, err := conn.WriteMsgUnix(data, unix.UnixRights(fds...), nil)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("short HTTP preparation message")
	}
	response := make([]byte, maxMessageBytes)
	n, err = conn.Read(response)
	if err != nil {
		return err
	}
	var reply preparationResponse
	if err = json.Unmarshal(response[:n], &reply); err != nil {
		return err
	}
	if reply.Error != "" {
		return fmt.Errorf("HTTP preparation: %s", reply.Error)
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
	data := make([]byte, maxMessageBytes)
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
	var message preparationMessage
	if err = json.Unmarshal(data[:n], &message); err != nil {
		return err
	}
	if message.Files != len(files) || len(files) == 0 || len(files) > MaxFiles {
		return errors.New("invalid HTTP preparation metadata")
	}
	deadline := time.Unix(0, message.Deadline)
	if deadline.After(accepted.Add(Budget)) {
		deadline = accepted.Add(Budget)
	}
	requestCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err = requestCtx.Err(); err != nil {
		return err
	}
	owned := files
	files = nil // handler adopts descriptors even on timeout/rejection
	result, prepareErr := handler(requestCtx, owned, kernelio.HTTPPreparationOptions{Source: message.Source})
	reply := preparationResponse{Result: result}
	if prepareErr != nil {
		reply.Error = "target preparation incomplete"
	}
	payload, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	_, err = conn.Write(payload)
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
