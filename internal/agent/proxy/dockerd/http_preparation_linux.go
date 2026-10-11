//go:build linux

package dockerd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
	"golang.org/x/sys/unix"
)

func resolveDockerTarget(ctx context.Context, upstreamSocket, id string, isExec bool) (httpprepare.Process, error) {
	var daemonPID atomic.Int32
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		c, err := dialer.DialContext(ctx, "unix", upstreamSocket)
		if err != nil {
			return nil, err
		}
		raw, err := c.(*net.UnixConn).SyscallConn()
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		var credential *unix.Ucred
		var credentialErr error
		err = raw.Control(func(fd uintptr) {
			credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		})
		if err != nil || credentialErr != nil || credential == nil || credential.Pid <= 0 {
			_ = c.Close()
			return nil, errors.New("docker daemon PID unavailable")
		}
		daemonPID.Store(credential.Pid)
		return c, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	inspect := func(path string, out any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("docker inspect returned %d", resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	containerID := id
	if isExec {
		var exec struct {
			ContainerID string
		}
		if err := inspect("/exec/"+id+"/json", &exec); err != nil {
			return httpprepare.Process{}, err
		}
		containerID = exec.ContainerID
	}
	if !fullDockerID(containerID) {
		return httpprepare.Process{}, errors.New("invalid Docker container identity")
	}
	var container struct {
		ID    string
		State struct {
			Pid     int32
			Running bool
		}
	}
	if err := inspect("/containers/"+containerID+"/json", &container); err != nil {
		return httpprepare.Process{}, err
	}
	if container.ID != containerID || !container.State.Running || container.State.Pid <= 0 {
		return httpprepare.Process{}, errors.New("docker container is not running")
	}
	return httpprepare.Process{PID: int(container.State.Pid), DaemonPID: int(daemonPID.Load())}, nil
}
