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
	"os"
	"sync/atomic"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"golang.org/x/sys/unix"
)

func prepareDockerTarget(ctx context.Context, upstreamSocket, id string, isExec bool, preparation *httpprepare.Preparation) error {
	if err := preparation.Available(ctx); err != nil {
		return err
	}
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
	containerID, command, source := id, "", "docker-start"
	if isExec {
		var exec struct {
			ContainerID   string
			ProcessConfig struct{ Entrypoint string }
		}
		if err := inspect("/exec/"+id+"/json", &exec); err != nil {
			return err
		}
		containerID, command, source = exec.ContainerID, exec.ProcessConfig.Entrypoint, "docker-exec"
	}
	if !fullDockerID(containerID) {
		return errors.New("invalid Docker container identity")
	}
	var container struct {
		ID    string
		State struct {
			Pid     int32
			Running bool
		}
		Config struct{ Env, Entrypoint, Cmd []string }
	}
	if err := inspect("/containers/"+containerID+"/json", &container); err != nil {
		return err
	}
	if container.ID != containerID || !container.State.Running || container.State.Pid <= 0 {
		return errors.New("docker container is not running")
	}
	root, err := dockerProcessRoot(daemonPID.Load(), container.State.Pid)
	if err != nil {
		return err
	}
	args := []string{command}
	if !isExec {
		args = append(container.Config.Entrypoint, container.Config.Cmd...)
	}
	return preparation.Prepare(ctx, root, httpprepare.BinDirectories(args, container.Config.Env), kernelio.HTTPPreparationOptions{Source: source})
}

// Docker inspect PID is relative to the daemon's PID namespace. Use that
// daemon's procfs view, and verify its namespace before interpreting the PID.
// No private overlay2/snapshot layout or remote-daemon filesystem is consulted.
func dockerProcessRoot(daemonPID, containerPID int32) (string, error) {
	if daemonPID <= 0 || containerPID <= 0 {
		return "", errors.New("invalid Docker process PID")
	}
	daemonRoot := fmt.Sprintf("/proc/%d/root", daemonPID)
	namespace, err := os.Stat(fmt.Sprintf("/proc/%d/ns/pid", daemonPID))
	if err != nil {
		return "", err
	}
	procNamespace, err := os.Stat(daemonRoot + "/proc/1/ns/pid")
	if err != nil {
		return "", err
	}
	if !os.SameFile(namespace, procNamespace) {
		return "", errors.New("docker daemon procfs PID namespace mismatch")
	}
	return fmt.Sprintf("%s/proc/%d/root", daemonRoot, containerPID), nil
}
