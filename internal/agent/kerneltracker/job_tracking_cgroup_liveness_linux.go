//go:build linux

package kerneltracker

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func scanLiveCgroups(cgroupV2RootPath string) (cgroupLivenessSnapshot, error) {
	return scanLiveCgroupsWithWalkDir(cgroupV2RootPath, filepath.WalkDir)
}

// scanLiveCgroupsWithWalkDir collects cgroup v2 directory IDs and paths.
// KernelTracker already treats cgroup IDs as cgroup directory inodes, so the
// live set can be compared directly with tracked_cgroups userspace state.
func scanLiveCgroupsWithWalkDir(cgroupV2RootPath string, walkDir func(string, fs.WalkDirFunc) error) (cgroupLivenessSnapshot, error) {
	if cgroupV2RootPath == "" {
		return cgroupLivenessSnapshot{}, errors.New("cgroup v2 root path is empty")
	}

	snapshot := cgroupLivenessSnapshot{LiveCgroups: make(map[uint64]string)}
	err := walkDir(cgroupV2RootPath, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Only a child ENOENT is safe to skip: it means the cgroup
			// disappeared during the scan. Other child errors could hide a
			// live subtree, so abort instead of falsely reconciling it away.
			if current != cgroupV2RootPath && errors.Is(walkErr, os.ErrNotExist) {
				snapshot.StatErrorCount++
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}

		var stat unix.Stat_t
		if err := unix.Stat(current, &stat); err != nil {
			// A child cgroup can disappear while the scan is walking the tree.
			// Treat that as a missed live entry, not as a failed reconciliation.
			if current != cgroupV2RootPath && errors.Is(err, os.ErrNotExist) {
				snapshot.StatErrorCount++
				return nil
			}
			return fmt.Errorf("stat cgroup path %q: %w", current, err)
		}
		snapshot.LiveCgroups[stat.Ino] = current
		snapshot.DirectoryCount++
		return nil
	})
	if err != nil {
		return cgroupLivenessSnapshot{}, fmt.Errorf("walk cgroup v2 root %q: %w", cgroupV2RootPath, err)
	}
	return snapshot, nil
}
