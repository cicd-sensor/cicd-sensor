//go:build linux

package kerneltracker

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"golang.org/x/sys/unix"
)

// scanTrackedCgroupPIDs walks the cgroup root, matches directories by inode to
// the tracked IDs, and reads their cgroup.procs — the PID side of HTTP uprobe
// reclaim (PIDs from cgroup.procs, not processesByJob, which can miss events).
// ENOENT mid-scan is the normal race (PIDsGone); any other error marks the
// snapshot incomplete (fail-keep). The periodic ticker that calls this is added
// by the default-on change; until then reclaim is driven via
// KernelIO.ReconcileHTTPUprobeTargets (tests).
func scanTrackedCgroupPIDs(cgroupV2RootPath string, cgroupIDs map[uint64]struct{}, scanStartedAt time.Time) kernelio.MappedProcessSnapshot {
	return scanTrackedCgroupPIDsWithWalkDir(cgroupV2RootPath, cgroupIDs, scanStartedAt, filepath.WalkDir)
}

func scanTrackedCgroupPIDsWithWalkDir(cgroupV2RootPath string, cgroupIDs map[uint64]struct{}, scanStartedAt time.Time, walkDir func(string, fs.WalkDirFunc) error) kernelio.MappedProcessSnapshot {
	complete := true
	var pids []int32
	scanned, gone, readErrs := 0, 0, 0
	remaining := len(cgroupIDs)

	err := walkDir(cgroupV2RootPath, func(current string, entry fs.DirEntry, walkErr error) error {
		if remaining == 0 {
			return fs.SkipAll
		}
		if walkErr != nil {
			if current != cgroupV2RootPath && errors.Is(walkErr, os.ErrNotExist) {
				gone++
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		var stat unix.Stat_t
		if err := unix.Stat(current, &stat); err != nil {
			if current != cgroupV2RootPath && errors.Is(err, os.ErrNotExist) {
				gone++
				return nil
			}
			return err
		}
		if _, tracked := cgroupIDs[stat.Ino]; !tracked {
			return nil
		}
		remaining--
		scanned++
		procs, malformed, err := readCgroupProcs(filepath.Join(current, "cgroup.procs"))
		switch {
		case err == nil:
			pids = append(pids, procs...)
			if malformed > 0 {
				readErrs += malformed
				complete = false // a hidden PID could be a live mapper
			}
		case errors.Is(err, os.ErrNotExist):
			gone++ // cgroup removed between stat and read: normal race
		default:
			readErrs++
			complete = false // could hide live processes: fail-keep
		}
		return nil
	})
	if err != nil {
		// A failed walk could have skipped a live tracked cgroup entirely.
		readErrs++
		complete = false
	}
	return kernelio.NewMappedProcessSnapshot(scanStartedAt, complete, pids, scanned, gone, readErrs)
}

// readCgroupProcs returns the PIDs in a cgroup.procs file and how many lines
// could not be parsed (each may hide a PID).
func readCgroupProcs(path string) (pids []int32, malformed int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		pid, perr := strconv.ParseInt(scanner.Text(), 10, 32)
		if perr != nil {
			malformed++
			continue
		}
		pids = append(pids, int32(pid))
	}
	return pids, malformed, scanner.Err()
}
