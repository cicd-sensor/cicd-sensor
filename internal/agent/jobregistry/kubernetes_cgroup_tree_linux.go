//go:build linux

package jobregistry

import (
	"context"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// bindPodCgroupTreeForProcess is a GitHub Kubernetes start-policy hook.
// KernelTracker owns /proc cgroup parsing and cgroup ID binding detail.
func (jr *JobRegistry) bindPodCgroupTreeForProcess(ctx context.Context, identity jobcontext.JobIdentity, rootPID int32) {
	result, err := jr.kernelTracker.BindPodCgroupTreeForProcess(ctx, identity, rootPID)
	if err != nil {
		jr.logger.WarnContext(ctx, "github_k8s_pod_cgroup_tree_bind_skipped",
			"job_identity", identity,
			"root_pid", rootPID,
			"error", err,
		)
		return
	}
	jr.logger.InfoContext(ctx, "github_k8s_pod_cgroup_tree_bound",
		"job_identity", identity,
		"root_pid", rootPID,
		"pod_cgroup_path", result.PodCgroupPath,
		"candidate_cgroups", result.CandidateCgroups,
		"bound_cgroups", result.BoundCgroups,
	)
}
