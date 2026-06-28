//go:build !linux

package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"

func scanLiveCgroupIDs(string) (cgroupLivenessSnapshot, error) {
	return cgroupLivenessSnapshot{}, kernelio.ErrNotSupported
}
