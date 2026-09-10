//go:build linux

// Package cgroupfs resolves cgroup v2 membership in the caller's node view.
package cgroupfs

import (
	"bufio"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ID reads /proc/PID/cgroup and resolves it against the full node cgroup mount.
// Read the FD in the Agent: procfs renders membership relative to the reader's
// cgroup namespace, even if another process opened the FD and sent it here.
func ID(r io.Reader, root string) (uint64, error) {
	if root == "" {
		return 0, errors.New("cgroup v2 root path is empty")
	}
	scanner := bufio.NewScanner(io.LimitReader(r, 8192))
	for scanner.Scan() {
		if path, found := strings.CutPrefix(scanner.Text(), "0::"); found {
			if strings.HasSuffix(path, " (deleted)") {
				return 0, errors.New("cgroup was deleted")
			}
			if !filepath.IsAbs(path) {
				return 0, errors.New("cgroup path is not absolute")
			}
			for component := range strings.SplitSeq(path, "/") {
				if component == ".." {
					return 0, errors.New("cgroup outside node namespace")
				}
			}
			var st unix.Stat_t
			if err := unix.Stat(filepath.Join(root, path), &st); err != nil {
				return 0, err
			}
			return st.Ino, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("no cgroup v2 entry found")
}
