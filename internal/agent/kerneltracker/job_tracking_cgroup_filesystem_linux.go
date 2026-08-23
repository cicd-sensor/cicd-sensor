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

func scanCgroupFilesystem(cgroupV2RootPath string) (cgroupFilesystemSnapshot, error) {
	return scanCgroupFilesystemWithWalkDir(cgroupV2RootPath, filepath.WalkDir)
}

// scanCgroupFilesystemWithWalkDir collects cgroup v2 directory IDs and paths.
// KernelTracker already treats cgroup IDs as cgroup directory inodes, so the
// live set can be compared directly with tracked_cgroups userspace state.
func scanCgroupFilesystemWithWalkDir(cgroupV2RootPath string, walkDir func(string, fs.WalkDirFunc) error) (cgroupFilesystemSnapshot, error) {
	if cgroupV2RootPath == "" {
		return cgroupFilesystemSnapshot{}, errors.New("cgroup v2 root path is empty")
	}

	snapshot := cgroupFilesystemSnapshot{CgroupPathsByID: make(map[uint64]string)}
	err := walkDir(cgroupV2RootPath, func(cgroupPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Only a child ENOENT is safe to skip: it means the cgroup
			// disappeared during the scan. Other child errors could hide a
			// live subtree, so abort instead of falsely reconciling it away.
			if cgroupPath != cgroupV2RootPath && errors.Is(walkErr, os.ErrNotExist) {
				snapshot.StatErrorCount++
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}

		var stat unix.Stat_t
		if err := unix.Stat(cgroupPath, &stat); err != nil {
			// A child cgroup can disappear while the scan is walking the tree.
			// Treat that as a missed live entry, not as a failed reconciliation.
			if cgroupPath != cgroupV2RootPath && errors.Is(err, os.ErrNotExist) {
				snapshot.StatErrorCount++
				return nil
			}
			return fmt.Errorf("stat cgroup path %q: %w", cgroupPath, err)
		}
		snapshot.CgroupPathsByID[stat.Ino] = cgroupPath
		snapshot.DirectoryCount++
		return nil
	})
	if err != nil {
		return cgroupFilesystemSnapshot{}, fmt.Errorf("walk cgroup v2 root %q: %w", cgroupV2RootPath, err)
	}
	return snapshot, nil
}
