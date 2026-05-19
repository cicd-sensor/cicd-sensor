//go:build linux

package kerneltracker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func lookupProcessCgroupID(pid int32, cgroupV2RootPath string) (uint64, error) {
	procPath := fmt.Sprintf("/proc/%d/cgroup", pid)

	data, err := os.ReadFile(procPath)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", procPath, err)
	}

	return cgroupIDFromProcCgroupData(data, cgroupV2RootPath)
}

func cgroupIDFromProcCgroupData(data []byte, cgroupV2RootPath string) (uint64, error) {
	if cgroupV2RootPath == "" {
		return 0, errors.New("cgroup v2 root path is empty")
	}

	for len(data) > 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte{'\n'})
		if cgroupPath, ok := bytes.CutPrefix(line, []byte("0::")); ok {
			fullPath := filepath.Join(cgroupV2RootPath, strings.TrimPrefix(string(cgroupPath), "/"))

			var stat unix.Stat_t
			if err := unix.Stat(fullPath, &stat); err != nil {
				return 0, fmt.Errorf("stat cgroup path %q: %w", fullPath, err)
			}

			return stat.Ino, nil
		}
	}

	return 0, errors.New("no cgroup v2 entry found")
}
