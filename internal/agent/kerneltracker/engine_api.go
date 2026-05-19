package kerneltracker

import (
	"context"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

// JobForCgroupResult is the lookup outcome returned by KernelTracker.JobForCgroup.
type JobForCgroupResult struct {
	JobID jobcontext.JobIdentity
	Found bool
}

// RegisterJob registers a Job in the engine and returns the per-Job event
// channel. RegisterJob does not bind any cgroup; call BindProcessCgroupToJob
// when a start hook identifies a process inside the Job tree.
func (engine *KernelTracker) RegisterJob(ctx context.Context, jobID jobcontext.JobIdentity) (<-chan jobevent.EventRecord, error) {
	replyCh := make(chan registerJobReply, 1)

	select {
	case engine.inputCh <- commandRegisterJob{JobID: jobID, Reply: replyCh}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case reply := <-replyCh:
		return reply.EventCh, reply.Err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// BindProcessCgroupToJob resolves pid's cgroup and seeds tracked_cgroups so
// the Job owns events from that cgroup tree.
func (engine *KernelTracker) BindProcessCgroupToJob(ctx context.Context, jobID jobcontext.JobIdentity, pid int32) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	cgroup, err := lookupProcessCgroupID(pid, engine.cgroupV2RootPath)
	if err != nil {
		return fmt.Errorf("read cgroup for pid %d: %w", pid, err)
	}
	if cgroup == 0 {
		return fmt.Errorf("invalid cgroup id 0")
	}

	replyCh := make(chan error, 1)

	select {
	case engine.inputCh <- commandBindCgroup{JobID: jobID, CgroupID: cgroup, Reply: replyCh}:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-replyCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// JobForPeerPID resolves the Job for a control-socket peer PID. A peer that
// already exited is a miss, not an engine error.
func (engine *KernelTracker) JobForPeerPID(ctx context.Context, pid int32) (JobForCgroupResult, error) {
	if pid <= 0 {
		return JobForCgroupResult{}, nil
	}
	cgroupID, err := lookupProcessCgroupID(pid, engine.cgroupV2RootPath)
	if err != nil {
		return JobForCgroupResult{}, nil
	}
	return engine.JobForCgroup(ctx, cgroupID)
}

func (engine *KernelTracker) RemoveJob(ctx context.Context, jobID jobcontext.JobIdentity) error {
	replyCh := make(chan error, 1)

	select {
	case engine.inputCh <- commandRemoveJob{JobID: jobID, Reply: replyCh}:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-replyCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// StageCgroupBasenameForJob records a future cgroup basename so the kernel
// cgroup_mkdir hook can bind the matching cgroup to jobID as soon as it appears.
func (engine *KernelTracker) StageCgroupBasenameForJob(ctx context.Context, basename string, jobID jobcontext.JobIdentity) error {
	replyCh := make(chan error, 1)

	select {
	case engine.inputCh <- commandStageCgroupBasename{Basename: basename, JobID: jobID, Reply: replyCh}:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-replyCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// JobForCgroup returns the JobIdentity that owns cgroupID, if any.
func (engine *KernelTracker) JobForCgroup(ctx context.Context, cgroupID uint64) (JobForCgroupResult, error) {
	replyCh := make(chan JobForCgroupResult, 1)

	select {
	case engine.inputCh <- commandFindJobForCgroup{CgroupID: cgroupID, Reply: replyCh}:
	case <-ctx.Done():
		return JobForCgroupResult{}, ctx.Err()
	}

	select {
	case result := <-replyCh:
		return result, nil
	case <-ctx.Done():
		return JobForCgroupResult{}, ctx.Err()
	}
}
