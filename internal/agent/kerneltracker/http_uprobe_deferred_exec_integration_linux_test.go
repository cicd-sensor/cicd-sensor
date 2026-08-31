//go:build linux && bpf_integration

package kerneltracker

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"testing"
)

type deferredHTTPUprobeExec struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  bytes.Buffer
	done    bool
}

// prepareHTTPUprobeExec starts an external launcher before KernelIO creates its
// fanotify permission group. Production Agent code never launches Job commands.
// Keeping the launcher outside the group owner also avoids a Go test-only cycle:
// Linux os/exec uses CLONE_VFORK, so the group-owning process can wait for its
// own permission response before its fanotify goroutine gets scheduled.
func prepareHTTPUprobeExec(t *testing.T, target *exec.Cmd) *deferredHTTPUprobeExec {
	t.Helper()
	launcherArgs := []string{"-c", `IFS= read -r _; exec "$@"`, "cicd-sensor-http-uprobe-test", target.Path}
	launcherArgs = append(launcherArgs, target.Args[1:]...)
	launcher := exec.Command("/bin/sh", launcherArgs...)
	launcher.Dir = target.Dir
	launcher.Env = target.Env

	input, err := launcher.StdinPipe()
	if err != nil {
		t.Fatalf("create deferred exec input: %v", err)
	}
	deferred := &deferredHTTPUprobeExec{command: launcher, input: input}
	launcher.Stdout = &deferred.output
	launcher.Stderr = &deferred.output
	if err := launcher.Start(); err != nil {
		t.Fatalf("start deferred exec launcher: %v", err)
	}
	t.Cleanup(func() {
		if deferred.done {
			return
		}
		_ = deferred.input.Close()
		_ = deferred.command.Process.Kill()
		_ = deferred.command.Wait()
	})
	return deferred
}

func (d *deferredHTTPUprobeExec) run() ([]byte, error) {
	d.done = true
	_, writeErr := io.WriteString(d.input, "\n")
	closeErr := d.input.Close()
	waitErr := d.command.Wait()
	return d.output.Bytes(), errors.Join(writeErr, closeErr, waitErr)
}

func (d *deferredHTTPUprobeExec) pid() int32 {
	return int32(d.command.Process.Pid)
}
