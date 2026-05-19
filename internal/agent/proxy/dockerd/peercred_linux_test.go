//go:build linux

package dockerd

import (
	"context"
	"net"
	"testing"
)

func TestConnContextStoresPeerPID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	listener, err := net.Listen("unix", dir+"/proxy.sock")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
			return
		}
		close(accepted)
	}()

	client, err := net.Dial("unix", dir+"/proxy.sock")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	serverConn := <-accepted
	if serverConn == nil {
		t.Fatal("server did not accept connection")
	}
	defer serverConn.Close()

	ctx := connContext(context.Background(), serverConn)
	pid, ok := ctx.Value(peerPIDCtxKey{}).(int32)
	if !ok {
		t.Fatal("peer pid missing from context")
	}
	if pid <= 0 {
		t.Fatalf("peer pid = %d, want positive", pid)
	}
}
