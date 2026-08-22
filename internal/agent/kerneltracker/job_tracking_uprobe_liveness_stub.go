//go:build !linux

package kerneltracker

import (
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func scanTrackedCgroupPIDs(string, map[uint64]struct{}, time.Time) kernelio.MappedProcessSnapshot {
	return kernelio.MappedProcessSnapshot{}
}
