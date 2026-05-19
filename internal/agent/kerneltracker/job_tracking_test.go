package kerneltracker

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestStageCgroupBasename_AddsBothMirrors(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandStageCgroupBasename{
		Basename: "docker-cafef00d.scope",
		JobID:    jobID,
		Reply:    reply,
	})

	runTestEffects(t, state, effects)
	if err := <-reply; err != nil {
		t.Fatalf("StageCgroupBasename returned error: %v", err)
	}
	if owner, ok := state.stagingByBasename["docker-cafef00d.scope"]; !ok || owner != jobID {
		t.Fatalf("staging owner: got %+v ok=%v, want %+v", owner, ok, jobID)
	}
	assertEffectOrder(t, effects,
		stageCgroupBasename{},
	)
}

func TestStageCgroupBasename_IdempotentSameJob(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.putStaging("docker-cafef00d.scope", jobID)
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandStageCgroupBasename{
		Basename: "docker-cafef00d.scope",
		JobID:    jobID,
		Reply:    reply,
	})

	runTestEffects(t, state, effects)
	if err := <-reply; err != nil {
		t.Fatalf("same-job duplicate StageCgroupBasename returned error: %v", err)
	}
	if got := len(state.stagingByBasename); got != 1 {
		t.Fatalf("same-job duplicate changed basename count: got %d, want 1", got)
	}
	if got := len(state.stagingByJob[jobID]); got != 1 {
		t.Fatalf("same-job duplicate changed reverse index count: got %d, want 1", got)
	}
	assertEffectOrder(t, effects,
		stageCgroupBasename{},
	)
}

func TestRegisterJob_RepliesWithoutMapEffect(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	reply := make(chan registerJobReply, 1)

	effects := handleEngineInput(state, commandRegisterJob{
		JobID: jobID,
		Reply: reply,
	})

	assertEffectOrder(t, effects,
		replyRegisterJob{},
	)
}

func TestBindCgroup_UpdatesKernelBeforeMirror(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, defaultEventRecordBufferSize)
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandBindCgroup{
		JobID:    jobID,
		CgroupID: 42,
		Reply:    reply,
	})

	if _, ok := state.jobForCgroup(42); ok {
		t.Fatalf("bind mutated userspace state before kernel effect ran")
	}
	runTestEffects(t, state, effects)
	if err := <-reply; err != nil {
		t.Fatalf("BindCgroup returned error: %v", err)
	}
	if owner, ok := state.jobForCgroup(42); !ok || owner != jobID {
		t.Fatalf("bind did not update userspace state after kernel effect: owner=%v ok=%v", owner, ok)
	}
	assertEffectOrder(t, effects,
		bindTrackedCgroup{},
	)
}

func TestBindCgroup_KernelFailureDoesNotMutateState(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, defaultEventRecordBufferSize)
	wantErr := errors.New("kernel tracked cgroup put failed")
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandBindCgroup{
		JobID:    jobID,
		CgroupID: 42,
		Reply:    reply,
	})

	kernelIO := &recordingKernelIO{putTrackedErr: wantErr}
	engine := newTestKernelTracker(nil, nil, kernelIO, "")
	engine.jobTracking = state
	engine.runEngineEffects(context.Background(), effects)

	if err := <-reply; !errors.Is(err, wantErr) {
		t.Fatalf("BindCgroup error = %v, want %v", err, wantErr)
	}
	if _, ok := state.jobForCgroup(42); ok {
		t.Fatalf("failed kernel tracked cgroup put mutated userspace state")
	}
}

func TestRemoveJob_DeletesKernelEntriesBeforeStateCleanup(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	channel := state.registerJob(jobID, defaultEventRecordBufferSize)
	state.bind(jobID, 42)
	state.bind(jobID, 84)
	state.putStaging("docker-cafef00d.scope", jobID)
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandRemoveJob{JobID: jobID, Reply: reply})

	if _, registered := state.jobs[jobID]; !registered {
		t.Fatalf("remove mutated userspace state before kernel cleanup ran")
	}
	kernelIO := runTestEffects(t, state, effects)
	if err := <-reply; err != nil {
		t.Fatalf("RemoveJob returned error: %v", err)
	}
	slices.Sort(kernelIO.deleteTracked)
	if !reflect.DeepEqual(kernelIO.deleteTracked, []uint64{42, 84}) {
		t.Fatalf("tracked cgroup deletes: got %#v, want [42 84]", kernelIO.deleteTracked)
	}
	if !reflect.DeepEqual(kernelIO.deleteStaging, []string{"docker-cafef00d.scope"}) {
		t.Fatalf("staging deletes: got %#v, want docker-cafef00d.scope", kernelIO.deleteStaging)
	}
	if _, registered := state.jobs[jobID]; registered {
		t.Fatalf("job still present after remove effect")
	}
	select {
	case _, ok := <-channel:
		if ok {
			t.Fatalf("event channel yielded a value instead of closing")
		}
	default:
		t.Fatalf("event channel was not closed after successful remove")
	}
	assertEffectOrder(t, effects,
		removeJobFromKernel{},
	)
}

func TestRemoveJob_KernelFailureDoesNotCleanupState(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.registerJob(jobID, defaultEventRecordBufferSize)
	state.bind(jobID, 42)
	state.putStaging("docker-cafef00d.scope", jobID)
	wantErr := errors.New("kernel tracked cgroup delete failed")
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandRemoveJob{JobID: jobID, Reply: reply})

	kernelIO := &recordingKernelIO{deleteTrackedErr: wantErr}
	engine := newTestKernelTracker(nil, nil, kernelIO, "")
	engine.jobTracking = state
	engine.runEngineEffects(context.Background(), effects)

	if err := <-reply; !errors.Is(err, wantErr) {
		t.Fatalf("RemoveJob error = %v, want %v", err, wantErr)
	}
	if _, registered := state.jobs[jobID]; !registered {
		t.Fatalf("failed kernel cleanup removed job")
	}
	if owner, ok := state.jobForCgroup(42); !ok || owner != jobID {
		t.Fatalf("failed kernel cleanup removed cgroup mirror: owner=%v ok=%v", owner, ok)
	}
	if owner, ok := state.stagingByBasename["docker-cafef00d.scope"]; !ok || owner != jobID {
		t.Fatalf("failed kernel cleanup removed staging mirror: owner=%v ok=%v", owner, ok)
	}
}

func TestRemoveJob_UnknownJobRepliesWithoutKernelCleanup(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "missing")
	state := newJobTrackingState()
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandRemoveJob{JobID: jobID, Reply: reply})

	assertEffectOrder(t, effects,
		replyRemoveJob{},
	)
	runTestEffects(t, state, effects)
	if err := <-reply; err != nil {
		t.Fatalf("RemoveJob unknown job error = %v, want nil", err)
	}
}

func TestStageCgroupBasename_RejectsCrossJobBasename(t *testing.T) {
	t.Parallel()

	first := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	second := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "456")
	state := newJobTrackingState()
	state.putStaging("docker-cafef00d.scope", first)
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandStageCgroupBasename{
		Basename: "docker-cafef00d.scope",
		JobID:    second,
		Reply:    reply,
	})

	if err := singleStageCgroupBasenameReply(t, effects); err == nil {
		t.Fatalf("expected error for cross-job staging basename")
	}
	if owner, ok := state.stagingByBasename["docker-cafef00d.scope"]; !ok || owner != first {
		t.Fatalf("cross-job conflict changed owner: got %+v ok=%v, want %+v true", owner, ok, first)
	}
	if _, ok := state.stagingByJob[second]["docker-cafef00d.scope"]; ok {
		t.Fatalf("cross-job conflict added reverse index for rejected job")
	}
}

func TestStageCgroupBasename_RejectsEmptyBasename(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandStageCgroupBasename{
		Basename: "",
		JobID:    jobID,
		Reply:    reply,
	})

	if err := singleStageCgroupBasenameReply(t, effects); err == nil {
		t.Fatalf("expected error for empty basename")
	}
	if len(state.stagingByBasename) != 0 {
		t.Fatalf("empty basename mutated state: count=%d", len(state.stagingByBasename))
	}
}

func TestStageCgroupBasename_RejectsOversizedBasename(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandStageCgroupBasename{
		Basename: strings.Repeat("a", kernelio.StagingKeyLen+1),
		JobID:    jobID,
		Reply:    reply,
	})

	if err := singleStageCgroupBasenameReply(t, effects); err == nil {
		t.Fatalf("expected error for oversized basename")
	}
	if len(state.stagingByBasename) != 0 {
		t.Fatalf("oversized basename mutated state: count=%d", len(state.stagingByBasename))
	}
}

func TestStageCgroupBasename_RejectsPathLikeBasename(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	reply := make(chan error, 1)

	effects := handleEngineInput(state, commandStageCgroupBasename{
		Basename: "/kubepods.slice/docker-cafef00d.scope",
		JobID:    jobID,
		Reply:    reply,
	})

	if err := singleStageCgroupBasenameReply(t, effects); err == nil {
		t.Fatalf("expected error for path-like basename")
	}
	if len(state.stagingByBasename) != 0 {
		t.Fatalf("path-like basename mutated state: count=%d", len(state.stagingByBasename))
	}
}

func TestStageCgroupBasename_KernelFailureDoesNotMutateState(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	wantErr := errors.New("kernel staging put failed")
	reply := make(chan error, 1)
	effects := handleEngineInput(state, commandStageCgroupBasename{
		Basename: "docker-cafef00d.scope",
		JobID:    jobID,
		Reply:    reply,
	})

	kernelIO := &recordingKernelIO{putStagingErr: wantErr}
	engine := newTestKernelTracker(nil, nil, kernelIO, "")
	engine.jobTracking = state
	engine.runEngineEffects(context.Background(), effects)

	if err := <-reply; !errors.Is(err, wantErr) {
		t.Fatalf("StageCgroupBasename error = %v, want %v", err, wantErr)
	}
	if _, ok := state.stagingByBasename["docker-cafef00d.scope"]; ok {
		t.Fatalf("failed kernel staging put mutated userspace state")
	}
}

func singleStageCgroupBasenameReply(t *testing.T, effects []engineEffect) error {
	t.Helper()
	for _, e := range effects {
		if reply, ok := e.(replyStageCgroupBasename); ok {
			return reply.Err
		}
	}
	t.Fatalf("no replyStageCgroupBasename engineEffect found in %#v", effects)
	return nil
}

func assertEffectOrder(t *testing.T, effects []engineEffect, want ...engineEffect) {
	t.Helper()
	if len(effects) != len(want) {
		t.Fatalf("effect count: got %d (%#v), want %d", len(effects), effects, len(want))
	}
	for i := range want {
		if reflect.TypeOf(effects[i]) != reflect.TypeOf(want[i]) {
			t.Fatalf("effect[%d]: got %T, want %T (all effects=%#v)", i, effects[i], want[i], effects)
		}
	}
}
