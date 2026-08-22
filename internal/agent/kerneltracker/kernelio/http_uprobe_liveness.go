package kernelio

import "time"

// HTTPUprobeLivenessSnapshot is one cgroup-liveness observation for tracked
// cgroups. The Linux worker expands the paths through cgroup.procs so PID
// discovery and process map scanning stay in the same owner.
type HTTPUprobeLivenessSnapshot struct {
	ScanStartedAt time.Time
	Complete      bool
	CgroupPaths   []string
}
