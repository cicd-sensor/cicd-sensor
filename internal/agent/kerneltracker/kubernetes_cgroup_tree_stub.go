//go:build !linux

package kerneltracker

import (
	"context"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// PodCgroupTreeBindResult summarizes a Kubernetes Pod cgroup tree bind attempt.
type PodCgroupTreeBindResult struct {
	PodCgroupPath    string
	CandidateCgroups int
	BoundCgroups     int
}

func (engine *KernelTracker) BindPodCgroupTreeForProcess(context.Context, jobcontext.JobIdentity, int32) (PodCgroupTreeBindResult, error) {
	_ = engine
	return PodCgroupTreeBindResult{}, kernelio.ErrNotSupported
}
