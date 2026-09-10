//go:build linux

package kerneltracker

import (
	"bytes"
	"fmt"
	"os"

	"github.com/cicd-sensor/cicd-sensor/internal/cgroupfs"
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
	return cgroupfs.ID(bytes.NewReader(data), cgroupV2RootPath)
}
