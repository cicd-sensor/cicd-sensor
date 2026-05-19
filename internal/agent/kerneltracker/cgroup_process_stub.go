//go:build !linux

package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"

func lookupProcessCgroupID(pid int32, cgroupV2RootPath string) (uint64, error) {
	_ = pid
	_ = cgroupV2RootPath
	return 0, kernelio.ErrNotSupported
}
