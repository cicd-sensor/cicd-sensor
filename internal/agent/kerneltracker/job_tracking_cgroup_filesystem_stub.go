//go:build !linux

package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"

func scanCgroupFilesystem(string) (cgroupFilesystemSnapshot, error) {
	return cgroupFilesystemSnapshot{}, kernelio.ErrNotSupported
}
