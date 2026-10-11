//go:build linux

package httpprepare

import (
	"errors"
	"fmt"
	"os"
)

// OpenProc pins the process directory before reading its cgroup or root.
// The returned FD belongs to the worker and never crosses a process boundary.
func (p Process) OpenProc() (*os.File, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/proc/%d", p.PID)
	if p.DaemonPID != 0 {
		daemon, err := os.Open(fmt.Sprintf("/proc/%d", p.DaemonPID))
		if err != nil {
			return nil, err
		}
		defer daemon.Close()
		base := fmt.Sprintf("/proc/self/fd/%d", daemon.Fd())
		namespace, err := os.Stat(base + "/ns/pid")
		if err != nil {
			return nil, err
		}
		procNamespace, err := os.Stat(base + "/root/proc/1/ns/pid")
		if err != nil {
			return nil, err
		}
		if !os.SameFile(namespace, procNamespace) {
			return nil, errors.New("docker daemon procfs PID namespace mismatch")
		}
		path = fmt.Sprintf("%s/root/proc/%d", base, p.PID)
	}
	return os.Open(path)
}
