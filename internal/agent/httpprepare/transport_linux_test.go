//go:build linux

package httpprepare

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

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
		name                string
		invalid             bool
		count               int
		large, handlerError bool
		called              bool
	}{
		{name: "exact unlinked FD is transferred with CLOEXEC", count: 1, called: true},
		{name: "handler failure still releases its adopted FD", count: 1, handlerError: true, called: true},
		{name: "unknown request byte skips handler", count: 1, invalid: true},
		{name: "empty FD packet skips handler"},
		{name: "truncated FD packet closes received descriptors", count: MaxFiles + 1},
		{name: "truncated packet skips handler", count: 1, large: true},
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
			called := false
			done := make(chan error, 1)
			go func() {
				done <- serveConnection(t.Context(), server, func(ctx context.Context, files []*os.File, source string, membership *os.File) error {
					called = true
					defer membership.Close()
					defer CloseFiles(files)
					gotDeadline, ok := ctx.Deadline()
					if !ok || time.Until(gotDeadline) <= 0 || time.Until(gotDeadline) > Budget {
						return errors.New("handler exceeded preparation deadline")
					}
					if len(files) != 1 || source != "remote" || membership == nil {
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
			data := []byte{1}
			if tc.invalid {
				data = []byte{2}
			}
			if tc.large {
				data = make([]byte, 2)
			}
			fds := make([]int, tc.count)
			if tc.count > 0 {
				fds = make([]int, tc.count+1)
			}
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
				buf := make([]byte, 1)
				n, err := client.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				want := byte(0)
				if tc.handlerError {
					want = 1
				}
				if n != 1 || buf[0] != want {
					t.Fatalf("reply=%v want=%d", buf[:n], want)
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

func TestPrepareRemoteReply(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reply   []byte
		wantErr bool
	}{
		{name: "complete", reply: []byte{0}},
		{name: "incomplete", reply: []byte{1}, wantErr: true},
		{name: "unknown status", reply: []byte{2}, wantErr: true},
		{name: "truncated reply", reply: []byte{0, 0}, wantErr: true},
		{name: "closed peer", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testProcessRoot(t)
			if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "usr/bin/gh"), []byte("fixture"), 0o755); err != nil {
				t.Fatal(err)
			}
			socket := filepath.Join(t.TempDir(), "prep.sock")
			listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socket, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				data, oob := make([]byte, 1), make([]byte, unix.CmsgSpace((MaxFiles+1)*4))
				_, n, _, _, err := conn.ReadMsgUnix(data, oob)
				files, parseErr := receivedFiles(oob[:n])
				CloseFiles(files)
				if err == nil && tc.reply != nil {
					_, err = conn.Write(tc.reply)
				}
				done <- errors.Join(err, parseErr)
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err = prepareRemote(ctx, socket, func(context.Context) (string, error) { return root, nil })
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
