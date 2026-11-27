package jobregistry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// Finalization entrypoints:
//   - FinalizeAll, FinalizeExpiredJobs, and RequestGitHubHostEnd are synchronous.
//   - OnJobEnded is asynchronous because it is called from the KernelTracker loop.
//
// finalizeTakenJobSync is the shared synchronous primitive. Callers must first
// remove the Job from the registry with takeJob.

// FinalizeAll synchronously finalizes every job with the given reason.
func (jr *JobRegistry) FinalizeAll(ctx context.Context, reason kerneltracker.EndReason) {
	jr.mu.Lock()
	identities := make([]jobcontext.JobIdentity, 0, len(jr.jobs))
	for identity := range jr.jobs {
		identities = append(identities, identity)
	}
	jr.mu.Unlock()

	for _, identity := range identities {
		job, ok := jr.takeJob(identity)
		if !ok {
			continue
		}
		if err := jr.finalizeTakenJobSync(ctx, job, reason, time.Now().UTC()); err != nil {
			jr.logger.WarnContext(ctx, "summary_emit_failed",
				"job_identity", job.Identity(),
				"error", err,
			)
		}
	}

	if len(identities) > 0 {
		jr.logger.InfoContext(ctx, "jobs_finalized",
			"reason", string(reason),
			"count", len(identities),
		)
	}
}

// FinalizeExpiredJobs synchronously finalizes jobs that have exceeded their TTL.
func (jr *JobRegistry) FinalizeExpiredJobs(ctx context.Context) {
	expiredJobs := make([]*job.Job, 0)
	for _, j := range jr.All() {
		if j.IsExpired() && j.State() != job.JobStateClosing {
			expiredJobs = append(expiredJobs, j)
		}
	}

	for _, j := range expiredJobs {
		job, ok := jr.takeJob(j.Identity())
		if !ok {
			continue
		}
		if err := jr.finalizeTakenJobSync(ctx, job, kerneltracker.EndTTL, time.Now().UTC()); err != nil {
			jr.logger.WarnContext(ctx, "summary_emit_failed",
				"job_identity", job.Identity(),
				"error", err,
			)
		}
		jr.logger.InfoContext(ctx, "job_reaped",
			"job_identity", job.Identity(),
			"started_at", job.StartedAt().UTC().Format(time.RFC3339),
			"deadline_at", job.DeadlineAt().UTC().Format(time.RFC3339),
		)
	}

	if len(expiredJobs) > 0 {
		jr.logger.InfoContext(ctx, "jobs_reaped",
			"reason", "ttl",
			"count", len(expiredJobs),
		)
	}
}

// OnJobEnded is the only async finalization entrypoint. It is called from the
// single KernelTracker loop, so it must hand off before calling finalizeTakenJobSync.
func (jr *JobRegistry) OnJobEnded(jobID jobcontext.JobIdentity, reason kerneltracker.EndReason) {
	go func() {
		ctx := context.Background()
		job, ok := jr.takeJob(jobID)
		if !ok {
			return
		}
		if err := jr.finalizeTakenJobSync(ctx, job, reason, time.Now().UTC()); err != nil {
			jr.logger.WarnContext(ctx, "summary_emit_failed",
				"job_identity", job.Identity(),
				"error", err,
			)
		}
	}()
}

// RequestGitHubHostEnd synchronously finalizes a GitHub Job that has a host
// scope. Hosted project-only Jobs keep using shutdown/TTL finalization.
func (jr *JobRegistry) RequestGitHubHostEnd(ctx context.Context, identity jobcontext.JobIdentity, peerPID int32) error {
	job := jr.get(identity)
	if job == nil {
		// Lenient on purpose: the CLI's job/health probe before this call is
		// the double-end failure guarantee (see postGitHubHostEnd).
		jr.logger.WarnContext(ctx, "host_end_job_not_found", "job_identity", identity)
		return nil
	}
	if job.HostScope() == nil {
		jr.logger.WarnContext(ctx, "host_end_without_host_scope", "job_identity", identity)
		return ErrHostScopeMissing
	}
	if err := jr.verifyPeerPIDBelongsToJob(ctx, peerPID, identity); err != nil {
		return err
	}
	job, ok := jr.takeJob(identity)
	if !ok {
		jr.logger.WarnContext(ctx, "host_end_job_not_found", "job_identity", identity)
		return nil
	}
	return jr.finalizeTakenJobSync(ctx, job, kerneltracker.EndHostEnd, time.Now().UTC())
}

type JobHealth struct {
	Identity      jobcontext.JobIdentity
	HostActive    bool
	ProjectActive bool
}

// GetGitHubJobHealth returns the active scope status for one GitHub Job.
func (jr *JobRegistry) GetGitHubJobHealth(ctx context.Context, identity jobcontext.JobIdentity, peerPID int32) (JobHealth, error) {
	job := jr.get(identity)
	if job == nil {
		jr.logger.WarnContext(ctx, "job_health_job_not_found", "job_identity", identity)
		return JobHealth{}, ErrJobNotFound
	}
	if err := jr.verifyPeerPIDBelongsToJob(ctx, peerPID, identity); err != nil {
		return JobHealth{}, err
	}
	return JobHealth{
		Identity:      identity,
		HostActive:    job.HostScope() != nil,
		ProjectActive: job.ProjectScope() != nil,
	}, nil
}

func closeOIDCForJob(job *job.Job) {
	if host := job.HostScope(); host != nil {
		host.CloseOIDCCredential()
	}
	if project := job.ProjectScope(); project != nil {
		project.CloseOIDCCredential()
	}
}

func (jr *JobRegistry) finalizeTakenJobSync(ctx context.Context, job *job.Job, reason kerneltracker.EndReason, finalizedAt time.Time) error {
	job.MarkClosing()
	defer closeOIDCForJob(job)

	jr.mu.Lock()
	kernelTracker := jr.kernelTracker
	removeJob := jr.removeJobHook
	jr.mu.Unlock()
	if kernelTracker != nil {
		// RemoveJob must run even when shutdown already canceled ctx.
		var err error
		if removeJob != nil {
			err = removeJob(context.Background(), job.Identity())
		} else {
			err = kernelTracker.RemoveJob(context.Background(), job.Identity())
		}
		if err != nil {
			return fmt.Errorf("remove bpf job: %w", err)
		}
	}
	jr.waitForDrain(ctx, job)
	// The summary is sent in parallel with the streaming flush so a kill
	// timer landing mid-drain cannot starve it behind the backlog (#143).
	// Safe: scope state is quiescent after the drain above and each send
	// has its own worker. Row ordering across log types is not promised.
	summaryIn := jobscope.SummaryLogInputs{
		Identity:   job.Identity(),
		Metadata:   job.Metadata(),
		RunnerType: job.RunnerType(),
		StartedAt:  job.StartedAt(),
	}
	var wg sync.WaitGroup
	var summaryErr error
	wg.Go(func() {
		var errs []error
		if host := job.HostScope(); host != nil {
			if err := host.EmitSummaryLog(ctx, summaryIn, string(reason), finalizedAt); err != nil {
				errs = append(errs, fmt.Errorf("emit host summary log: %w", err))
			}
		}
		if project := job.ProjectScope(); project != nil {
			if err := project.EmitSummaryLog(ctx, summaryIn, string(reason), finalizedAt); err != nil {
				errs = append(errs, fmt.Errorf("emit project summary log: %w", err))
			}
		}
		summaryErr = errors.Join(errs...)
	})
	if host := job.HostScope(); host != nil {
		wg.Go(func() {
			if err := host.FinalizeStreamingLogs(ctx); err != nil {
				jr.logger.WarnContext(ctx, "job_host_scope_finalize_failed", "error", err)
			}
		})
	}
	if project := job.ProjectScope(); project != nil {
		wg.Go(func() {
			if err := project.FinalizeStreamingLogs(ctx); err != nil {
				jr.logger.WarnContext(ctx, "job_project_scope_finalize_failed", "error", err)
			}
		})
	}
	wg.Wait()
	jr.logger.InfoContext(ctx, "job_finalized", "job_identity", job.Identity(), "reason", string(reason))
	return summaryErr
}

// drainProgressInterval spaces the progress logs of a slow drain. Five
// seconds keeps a 20-30s shutdown window readable without flooding journal.
const drainProgressInterval = 5 * time.Second

// waitForDrain blocks until the Job's event worker has consumed every
// delivered event, or until ctx is done (the shutdown grace). On ctx
// expiry the drain is truncated so Summary / streaming finalize can still
// run (#205); the worker keeps processing until the process exits.
// Completion is Done(), not an empty queue: the worker may still be
// inside the last event.
func (jr *JobRegistry) waitForDrain(ctx context.Context, job *job.Job) {
	queuedAtStart := job.QueuedEvents()
	started := time.Now()
	ticker := time.NewTicker(drainProgressInterval)
	defer ticker.Stop()
	logCompleted := func() {
		jr.logger.InfoContext(ctx, "job_drain_completed",
			"job_identity", job.Identity(),
			"queued_at_start", queuedAtStart,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	}
	for {
		select {
		case <-job.Done():
			logCompleted()
			return
		case <-ctx.Done():
			// Prefer Done when both are ready so a finished drain is not
			// reported as truncated (Go select picks at random otherwise).
			select {
			case <-job.Done():
				logCompleted()
			default:
				jr.logger.WarnContext(ctx, "job_drain_truncated",
					"job_identity", job.Identity(),
					"queued", job.QueuedEvents(),
					"elapsed_ms", time.Since(started).Milliseconds(),
				)
			}
			return
		case <-ticker.C:
			jr.logger.InfoContext(ctx, "job_drain_in_progress",
				"job_identity", job.Identity(),
				"queued", job.QueuedEvents(),
				"elapsed_ms", time.Since(started).Milliseconds(),
			)
		}
	}
}

func (jr *JobRegistry) takeJob(identity jobcontext.JobIdentity) (*job.Job, bool) {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	job, ok := jr.jobs[identity]
	if !ok {
		return nil, false
	}
	delete(jr.jobs, identity)
	return job, true
}
