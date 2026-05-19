package jobregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// FindJobForPeerPID resolves the Job that owns peerPID's cgroup tree.
// GitHub relies on this path; GitLab usually uses labels before promotion.
func (jr *JobRegistry) FindJobForPeerPID(ctx context.Context, peerPID int32) (identity jobcontext.JobIdentity, found bool, err error) {
	jr.mu.Lock()
	kernelTracker := jr.kernelTracker
	jr.mu.Unlock()
	if kernelTracker == nil {
		return jobcontext.JobIdentity{}, false, errors.New("kernel tracking disabled")
	}
	if peerPID <= 0 {
		return jobcontext.JobIdentity{}, false, nil
	}
	result, queryErr := kernelTracker.JobForPeerPID(ctx, peerPID)
	if queryErr != nil {
		return jobcontext.JobIdentity{}, false, queryErr
	}
	if !result.Found {
		return jobcontext.JobIdentity{}, false, nil
	}
	return result.JobID, true, nil
}

// StageCgroupBasenameForJob records a sibling-container staging entry.
// Pending jobs return ErrJobNotFound so lazy GitLab create can retry after
// host rules are attached instead of routing events into an empty scope.
func (jr *JobRegistry) StageCgroupBasenameForJob(ctx context.Context, basename string, identity jobcontext.JobIdentity) error {
	jr.mu.Lock()
	kernelTracker := jr.kernelTracker
	j := jr.jobs[identity]
	_, starting := jr.starting[identity]
	jr.mu.Unlock()

	if kernelTracker == nil {
		return errors.New("kernel tracking disabled")
	}
	if starting || j == nil {
		return ErrJobNotFound
	}
	return kernelTracker.StageCgroupBasenameForJob(ctx, basename, identity)
}

// bindStartProcessCgroupToJob seeds tracking from a start-hook process and
// removes the Job on failure. The KernelTracker keeps cgroup tracking as truth.
func (jr *JobRegistry) bindStartProcessCgroupToJob(ctx context.Context, identity jobcontext.JobIdentity, startPID int32, scope string) error {
	if startPID <= 0 {
		jr.removeJobAfterProcessCgroupBindFailure(ctx, identity, scope)
		return fmt.Errorf("bind process cgroup to job: invalid start pid %d", startPID)
	}
	if err := jr.kernelTracker.BindProcessCgroupToJob(ctx, identity, startPID); err != nil {
		jr.removeJobAfterProcessCgroupBindFailure(ctx, identity, scope)
		return fmt.Errorf("bind process cgroup to job: %w", err)
	}
	return nil
}

func (jr *JobRegistry) removeJobAfterProcessCgroupBindFailure(ctx context.Context, identity jobcontext.JobIdentity, scope string) {
	if jr.kernelTracker != nil {
		// Unwind should drain even if the caller canceled mid-start.
		if err := jr.kernelTracker.RemoveJob(context.Background(), identity); err != nil {
			jr.logger.WarnContext(ctx, scope+"_unwind_remove_failed",
				"job_identity", identity,
				"error", err,
			)
		}
	}
	jr.mu.Lock()
	delete(jr.jobs, identity)
	jr.mu.Unlock()
}

// verifyPeerPIDBelongsToJob gates project requests by checking that the request peer is
// already inside the tracked Job cgroup tree. Nil KernelTracker keeps dev builds usable.
func (jr *JobRegistry) verifyPeerPIDBelongsToJob(ctx context.Context, peerPID int32, identity jobcontext.JobIdentity) error {
	jr.mu.Lock()
	kernelTracker := jr.kernelTracker
	jr.mu.Unlock()
	if kernelTracker == nil {
		return nil
	}
	result, err := kernelTracker.JobForPeerPID(ctx, peerPID)
	if err != nil {
		return fmt.Errorf("job for process cgroup: %w", err)
	}
	if !result.Found || result.JobID != identity {
		return ErrPeerNotInJob
	}
	return nil
}
