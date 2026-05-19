package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/jobcontext"

type EndReason string

const (
	EndCgroupRmdir EndReason = "cgroup_rmdir"
	EndHostEnd     EndReason = "host_end"
	EndTTL         EndReason = "ttl"
	EndShutdown    EndReason = "shutdown"
	EndTerminate   EndReason = "terminate"
	EndError       EndReason = "error"
)

type JobEndNotifier interface {
	OnJobEnded(jobID jobcontext.JobIdentity, reason EndReason)
}
