//go:build linux

package httpprepare

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"golang.org/x/sys/unix"
)

func packetPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*net.UnixConn, 2)
	for i, fd := range pair {
		f := os.NewFile(uintptr(fd), "packet-test")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		connections[i] = c.(*net.UnixConn)
		t.Cleanup(func() { _ = c.Close() })
	}
	return connections[0], connections[1]
}

func TestServeConnection(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		source                       string
		count                        int
		remaining                    time.Duration
		expired, large, handlerError bool
		pin                          bool
		called                       bool
	}{
		{name: "exact unlinked FD is transferred with CLOEXEC", source: "docker-exec", count: 1, called: true},
		{name: "handler failure still releases its adopted FD", source: "nri-start", count: 1, handlerError: true, called: true},
		{name: "empty FD packet skips handler", source: "docker-exec"},
		{name: "truncated FD packet closes received descriptors", source: "docker-exec", count: MaxFiles + 1},
		{name: "sender remaining deadline is preserved", source: "docker-exec", count: 1, remaining: Budget / 2, called: true},
		{name: "distant sender deadline is clamped", source: "docker-exec", count: 1, remaining: 2 * Budget, called: true},
		{name: "wire metadata cannot request machine pin", source: "host-start", count: 1, pin: true, called: true},
		{name: "expired deadline skips handler", source: "nri-start", count: 1, expired: true},
		{name: "truncated packet skips handler", source: "nri-start", count: 1, large: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := packetPair(t)
			f, err := os.CreateTemp(t.TempDir(), "target")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(f.Name()); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			remaining := Budget
			if tc.remaining != 0 {
				remaining = tc.remaining
			}
			deadline := time.Now().Add(remaining)
			if tc.expired {
				deadline = time.Now().Add(-time.Second)
			}
			called := false
			done := make(chan error, 1)
			go func() {
				done <- serveConnection(t.Context(), server, func(ctx context.Context, files []*os.File, options kernelio.HTTPPreparationOptions) error {
					called = true
					defer CloseFiles(files)
					gotDeadline, ok := ctx.Deadline()
					if !ok || gotDeadline.After(deadline) || time.Until(gotDeadline) > Budget {
						return errors.New("handler exceeded preparation deadline")
					}
					if tc.remaining == Budget/2 && !gotDeadline.Equal(deadline) {
						return errors.New("sender remaining deadline changed")
					}
					if len(files) != 1 || options.Pin {
						return errors.New("invalid handler input")
					}
					got, e := files[0].Stat()
					if e != nil || !os.SameFile(info, got) {
						return errors.New("transferred another inode")
					}
					flags, e := unix.FcntlInt(files[0].Fd(), unix.F_GETFD, 0)
					if e != nil || flags&unix.FD_CLOEXEC == 0 {
						return errors.New("missing CLOEXEC")
					}
					if tc.handlerError {
						return context.DeadlineExceeded
					}
					return nil
				})
			}()
			data, _ := json.Marshal(struct {
				preparationMessage
				Pin bool
			}{preparationMessage: preparationMessage{Source: tc.source, Deadline: deadline.UnixNano()}, Pin: tc.pin})
			if tc.large {
				data = make([]byte, maxMessageBytes+1)
			}
			fds := make([]int, tc.count)
			for i := range fds {
				fds[i] = int(f.Fd())
			}
			var rights []byte
			if len(fds) > 0 {
				rights = unix.UnixRights(fds...)
			}
			if _, _, err := client.WriteMsgUnix(data, rights, nil); err != nil {
				t.Fatal(err)
			}
			if tc.called {
				if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, maxMessageBytes)
				n, err := client.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				var reply preparationResponse
				if err := json.Unmarshal(buf[:n], &reply); err != nil {
					t.Fatal(err)
				}
				if tc.handlerError {
					if reply.Error == "" {
						t.Fatal("missing error reply")
					}
				} else if reply.Error != "" {
					t.Fatalf("reply=%+v", reply)
				}
			}
			err = <-done
			if called != tc.called || (err != nil) == tc.called {
				t.Fatalf("called=%v err=%v", called, err)
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != len(before) {
				t.Fatalf("FD leak: before=%d after=%d", len(before), len(after))
			}
		})
	}
}
