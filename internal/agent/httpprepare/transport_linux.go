//go:build linux

package httpprepare

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

type peerAllowedKey struct{}

// Serve accepts PIDs only on the node-owned 0600 socket, with a same-UID check.
// Handlers queue metadata and wait; they do not perform target filesystem I/O.
func Serve(ctx context.Context, socket string, prepare Handler, logger *slog.Logger) error {
	if prepare == nil {
		return errors.New("HTTP preparation handler required")
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("HTTP preparation path is not a socket")
		}
		c, e := net.DialTimeout("unix", socket, 50*time.Millisecond)
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
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0o600); err != nil {
		return err
	}
	server := &http.Server{
		Handler:     preparationHandler(prepare, logger),
		ReadTimeout: Budget, ReadHeaderTimeout: Budget, WriteTimeout: Budget, IdleTimeout: Budget, MaxHeaderBytes: 1024,
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			allowed := false
			raw, err := c.(*net.UnixConn).SyscallConn()
			if err == nil {
				err = raw.Control(func(fd uintptr) {
					credential, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
					allowed = e == nil && credential.Uid == uint32(os.Geteuid())
				})
			}
			return context.WithValue(ctx, peerAllowedKey{}, err == nil && allowed)
		},
	}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func preparationHandler(prepare Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed, _ := r.Context().Value(peerAllowedKey{}).(bool); !allowed {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/prepare" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		pid, err := strconv.Atoi(r.URL.Query().Get("pid"))
		daemon, daemonErr := strconv.Atoi(r.URL.Query().Get("daemon_pid"))
		process := Process{PID: pid, DaemonPID: daemon}
		if err != nil || daemonErr != nil || process.Validate() != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), Budget)
		defer cancel()
		if err := prepare(ctx, process); err != nil {
			if logger != nil {
				logger.DebugContext(ctx, "http_preparation_request_failed", "pid", pid, "error", err)
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
