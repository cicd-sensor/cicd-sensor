//go:build !linux

package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"

func scanLiveCgroups(string) (cgroupLivenessSnapshot, error) {
	return cgroupLivenessSnapshot{}, kernelio.ErrNotSupported
}
