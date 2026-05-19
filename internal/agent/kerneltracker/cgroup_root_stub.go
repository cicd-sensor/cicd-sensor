//go:build !linux

package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"

func getCgroupV2Root() (string, error) {
	return "", kernelio.ErrNotSupported
}
