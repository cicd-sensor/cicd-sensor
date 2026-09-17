//go:build linux

package httpprepare

import (
	"errors"
	"os"
	"path/filepath"
)

// Open without reading: the receiving Agent's cgroup namespace determines how
// procfs renders this process's membership. An open proc FD also pins the PID
// identity, so exit/reuse cannot silently select a new process.
func openProcessMembership(root string) (*os.File, error) {
	if filepath.Base(root) != "root" {
		return nil, errors.New("HTTP preparation needs a process root")
	}
	return os.Open(filepath.Join(filepath.Dir(root), "cgroup"))
}
