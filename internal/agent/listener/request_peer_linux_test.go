//go:build linux

package listener

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestRequestPeerPIDAndUIDFromUnixSocket(t *testing.T) {
	dir := newTestSocketDir(t, "cicd-sensor-peer-test-")
	defer os.RemoveAll(dir)

	socketPath := dir + "/peer.sock"
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		skipIfListenPermissionDenied(t, err)
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	clientConn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	defer clientConn.Close()

	var serverConn net.Conn
	select {
	case err := <-acceptErr:
		t.Fatalf("accept unix socket: %v", err)
	case serverConn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("accept timed out")
	}
	defer serverConn.Close()

	ctx := context.WithValue(context.Background(), unixConnKey{}, serverConn)
	pid, err := requestPeerPID(ctx)
	if err != nil {
		t.Fatalf("requestPeerPID: %v", err)
	}
	if pid != int32(os.Getpid()) {
		t.Fatalf("pid: got %d, want %d", pid, os.Getpid())
	}

	uid, err := requestPeerUID(ctx)
	if err != nil {
		t.Fatalf("requestPeerUID: %v", err)
	}
	if uid != uint32(os.Geteuid()) {
		t.Fatalf("uid: got %d, want %d", uid, os.Geteuid())
	}
}
