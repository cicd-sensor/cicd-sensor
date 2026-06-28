package kerneltracker

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestTransitionInvariants(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "register job is idempotent for same job",
			run: func(t *testing.T) {
				state := newJobTrackingState()
				replyOne := make(chan registerJobReply, 1)
				effects := handleEngineInput(state, commandRegisterJob{
					JobID: jobID,
					Reply: replyOne,
				})
				assertReplyCount(t, effects, 1)
				if _, registered := state.jobs[jobID]; !registered {
					t.Fatalf("job missing after first RegisterJob")
				}

				// Bind a cgroup so the second RegisterJob proves registration
				// does not overwrite existing cgroup ownership.
				bindReply := make(chan error, 1)
				bindEffects := handleEngineInput(state, commandBindCgroup{JobID: jobID, CgroupID: 42, Reply: bindReply})
				runTestEffects(t, state, bindEffects)
				if err := <-bindReply; err != nil {
					t.Fatalf("bind failed: %v", err)
				}

				replyTwo := make(chan registerJobReply, 1)
				sameEffects := handleEngineInput(state, commandRegisterJob{
					JobID: jobID,
					Reply: replyTwo,
				})

				assertReplyCount(t, sameEffects, 1)
				if _, registered := state.jobs[jobID]; !registered {
					t.Fatalf("job missing after idempotent RegisterJob")
				}
				if owner, ok := state.jobForCgroup(42); !ok || owner != jobID {
					t.Fatalf("jobByCgroup changed on idempotent RegisterJob")
				}
			},
		},
		{
			name: "bind cgroup rejects cgroup already bound to another job",
			run: func(t *testing.T) {
				other := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "999")
				state := destinationTrackedState(other, 42)

				// The new Job must be registered first. handleBindCgroup
				// errors out if the Job is unknown; we want to exercise the
				// "cgroup already bound" branch, not the "job unregistered"
				// branch.
				startReply := make(chan registerJobReply, 1)
				handleEngineInput(state, commandRegisterJob{
					JobID: jobID,
					Reply: startReply,
				})

				bindReply := make(chan error, 1)
				effects := handleEngineInput(state, commandBindCgroup{
					JobID:    jobID,
					CgroupID: 42,
					Reply:    bindReply,
				})

				assertReplyCount(t, effects, 1)
				if owner, ok := state.jobForCgroup(42); !ok || owner != other {
					t.Fatalf("collision must not change cgroup ownership: got %v ok=%v", owner, ok)
				}

				var got error
				for _, effect := range effects {
					if r, ok := effect.(replyBindCgroup); ok {
						got = r.Err
					}
				}
				if got == nil {
					t.Fatalf("collision must surface an error in replyBindCgroup")
				}
			},
		},
		{
			name: "bind cgroup rejects unknown job",
			run: func(t *testing.T) {
				state := newJobTrackingState()
				bindReply := make(chan error, 1)
				effects := handleEngineInput(state, commandBindCgroup{
					JobID:    jobID,
					CgroupID: 42,
					Reply:    bindReply,
				})

				assertReplyCount(t, effects, 1)
				if testHasTrackedCgroups(state, jobID) {
					t.Fatalf("bind for unregistered job must not bind")
				}
				var got error
				for _, effect := range effects {
					if r, ok := effect.(replyBindCgroup); ok {
						got = r.Err
					}
				}
				if got == nil {
					t.Fatalf("bind for unregistered job must surface an error")
				}
			},
		},
		{
			name: "remove job clears state",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42)
				effects := handleEngineInput(state, commandRemoveJob{JobID: jobID})
				runTestEffects(t, state, effects)

				if _, registered := state.jobs[jobID]; registered {
					t.Fatalf("job still present after remove")
				}
				if testHasTrackedCgroups(state, jobID) {
					t.Fatalf("tracking still has job after remove")
				}
				if _, ok := state.jobEventChannels[jobID]; ok {
					t.Fatalf("event channel still present after remove")
				}
				if len(effects) != 1 {
					t.Fatalf("remove job effects = %#v, want one cleanup effect", effects)
				}
			},
		},
		{
			name: "mkdir under tracked parent binds child cgroup",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42)

				effects := handleEngineInput(state, cgroupMkdirSample{
					CgroupID:       84,
					ParentCgroupID: 42,
					CgroupPath:     "/tracked/child",
				})

				if owner, ok := state.jobForCgroup(84); !ok || owner != jobID {
					t.Fatalf("child cgroup was not bound to tracked parent job")
				}
				if !testHasTrackedCgroups(state, jobID) {
					t.Fatalf("tracked job missing after child bind")
				}
				if len(effects) != 0 {
					t.Fatalf("mkdir should not emit effects after BPF-side tracking: %#v", effects)
				}
			},
		},
		{
			name: "mkdir under untracked parent is ignored",
			run: func(t *testing.T) {
				state := newJobTrackingState()

				effects := handleEngineInput(state, cgroupMkdirSample{
					CgroupID:       84,
					ParentCgroupID: 42,
					CgroupPath:     "/untracked/child",
				})

				if _, ok := state.jobForCgroup(84); ok {
					t.Fatalf("untracked mkdir unexpectedly bound child cgroup")
				}
				if len(effects) != 0 {
					t.Fatalf("untracked mkdir emitted unexpected effects: %#v", effects)
				}
			},
		},
		{
			name: "cgroup attach within same tracked job is a no-op",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42, 84)
				effects := handleEngineInput(state, cgroupAttachSample{
					Tgid:                100,
					SourceCgroupID:      42,
					DestinationCgroupID: 84,
				})

				if len(effects) != 0 {
					t.Fatalf("tracked move emitted effects: %#v", effects)
				}
				if owner, ok := state.jobForCgroup(42); !ok || owner != jobID {
					t.Fatalf("old tracked cgroup mapping changed")
				}
				if owner, ok := state.jobForCgroup(84); !ok || owner != jobID {
					t.Fatalf("new tracked cgroup mapping changed")
				}
			},
		},
		{
			name: "cgroup attach across tracked jobs preserves existing owner",
			run: func(t *testing.T) {
				otherJobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "456")
				var logs bytes.Buffer
				state := destinationTrackedState(jobID, 42)
				state.logger = slog.New(slog.NewJSONHandler(&logs, nil))
				state.registerJob(otherJobID, defaultEventRecordBufferSize)
				state.bind(otherJobID, 84)

				effects := handleEngineInput(state, cgroupAttachSample{
					Tgid:                100,
					SourceCgroupID:      42,
					DestinationCgroupID: 84,
				})

				if len(effects) != 0 {
					t.Fatalf("cross-job move emitted effects: %#v", effects)
				}
				if !strings.Contains(logs.String(), "bpf_cgroup_attach_owner_conflict") {
					t.Fatalf("cross-job move did not log owner conflict: %s", logs.String())
				}
				if owner, ok := state.jobForCgroup(42); !ok || owner != jobID {
					t.Fatalf("source cgroup owner changed on cross-job move")
				}
				if owner, ok := state.jobForCgroup(84); !ok || owner != otherJobID {
					t.Fatalf("destination cgroup owner changed on cross-job move")
				}
			},
		},
		{
			name: "cgroup attach escape extends tracking without event",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42)
				effects := handleEngineInput(state, cgroupAttachSample{
					Tgid:                100,
					SourceCgroupID:      42,
					DestinationCgroupID: 84,
				})

				if owner, ok := state.jobForCgroup(42); !ok || owner != jobID {
					t.Fatalf("jobByCgroup changed for source cgroup on escape")
				}
				if owner, ok := state.jobForCgroup(84); !ok || owner != jobID {
					t.Fatalf("destination cgroup not bound to escaping Job")
				}
				if len(effects) != 0 {
					t.Fatalf("escape emitted effects: %#v", effects)
				}
			},
		},
		{
			name: "cgroup attach ingress is a no-op",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 84)

				effects := handleEngineInput(state, cgroupAttachSample{
					Tgid:                100,
					SourceCgroupID:      42,
					DestinationCgroupID: 84,
				})

				if len(effects) != 0 {
					t.Fatalf("ingress emitted effects: %#v", effects)
				}
				if owner, ok := state.jobForCgroup(84); !ok || owner != jobID {
					t.Fatalf("jobByCgroup changed on ingress")
				}
			},
		},
		{
			name: "cgroup attach with neither side tracked is a no-op",
			run: func(t *testing.T) {
				state := newJobTrackingState()

				effects := handleEngineInput(state, cgroupAttachSample{
					Tgid:                100,
					SourceCgroupID:      42,
					DestinationCgroupID: 84,
				})

				if len(effects) != 0 {
					t.Fatalf("untracked attach emitted effects: %#v", effects)
				}
				if len(state.jobByCgroup) != 0 {
					t.Fatalf("state changed on fully untracked attach")
				}
			},
		},
		{
			name: "notify job ended only when last active cgroup is removed",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42, 84)
				partialEffects := handleEngineInput(state, cgroupRmdirSample{CgroupID: 42})
				if hasNotifyJobEndedEffect(partialEffects) {
					t.Fatalf("unexpected notifyJobEnded before last cgroup removal")
				}
				if len(partialEffects) != 0 {
					t.Fatalf("partial rmdir emitted effects: %#v", partialEffects)
				}

				finalEffects := handleEngineInput(state, cgroupRmdirSample{CgroupID: 84})
				if !hasNotifyJobEndedEffect(finalEffects) {
					t.Fatalf("expected notifyJobEnded when last cgroup was removed")
				}
				assertEffectOrder(t, finalEffects,
					notifyJobEnded{},
				)
			},
		},
		{
			name: "duplicate final cgroup rmdir does not notify twice",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42)
				firstEffects := handleEngineInput(state, cgroupRmdirSample{CgroupID: 42})
				if !hasNotifyJobEndedEffect(firstEffects) {
					t.Fatalf("expected notifyJobEnded when last active cgroup was removed")
				}

				secondEffects := handleEngineInput(state, cgroupRmdirSample{CgroupID: 42})
				if len(secondEffects) != 0 {
					t.Fatalf("duplicate rmdir emitted effects: %#v", secondEffects)
				}
			},
		},
		{
			name: "purge removed cgroups does not notify job ended",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42, 84)
				state.markTrackedCgroupRemoved(42, time.Now().UTC().Add(-cgroupRemovalGracePeriod-time.Second))

				effects := handleEngineInput(state, commandPurgeExpiredTrackingState{})
				if hasNotifyJobEndedEffect(effects) {
					t.Fatalf("purge emitted notifyJobEnded: %#v", effects)
				}
				assertEffectOrder(t, effects,
					deleteExpiredCgroupsFromKernel{},
				)
			},
		},
		{
			name: "cgroup liveness reconciliation notifies when final active cgroup is missing",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42)
				var logs bytes.Buffer
				state.logger = slog.New(slog.NewJSONHandler(&logs, nil))
				effects := handleEngineInput(state, commandReconcileCgroupLiveness{
					ScanStartedAt:  time.Now().UTC().Add(time.Second),
					CheckedAt:      time.Now().UTC().Add(2 * time.Second),
					LiveCgroupIDs:  map[uint64]struct{}{},
					StatErrorCount: 1,
				})
				if !hasNotifyJobEndedEffect(effects) {
					t.Fatalf("expected notifyJobEnded when final active cgroup is missing")
				}
				assertEffectOrder(t, effects,
					notifyJobEnded{},
				)
				logOutput := logs.String()
				for _, want := range []string{
					"cgroup_liveness_reconciled",
					`"removed_count":1`,
					`"drained_job_count":1`,
					`"live_cgroup_count":0`,
					`"stat_error_count":1`,
				} {
					if !strings.Contains(logOutput, want) {
						t.Fatalf("reconciliation log = %s, want to contain %s", logOutput, want)
					}
				}
			},
		},
		{
			name: "cgroup liveness reconciliation is silent when nothing changes",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42)
				var logs bytes.Buffer
				state.logger = slog.New(slog.NewJSONHandler(&logs, nil))
				effects := handleEngineInput(state, commandReconcileCgroupLiveness{
					ScanStartedAt: time.Now().UTC().Add(time.Second),
					CheckedAt:     time.Now().UTC().Add(2 * time.Second),
					LiveCgroupIDs: map[uint64]struct{}{42: {}},
				})
				if len(effects) != 0 {
					t.Fatalf("live cgroup reconciliation emitted effects: %#v", effects)
				}
				if got := logs.String(); got != "" {
					t.Fatalf("live cgroup reconciliation log = %s, want empty", got)
				}
			},
		},
		{
			name: "cgroup rmdir then liveness scan keeps non-final removed cgroup pending",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42, 84)
				rmdirEffects := handleEngineInput(state, cgroupRmdirSample{CgroupID: 42})
				if len(rmdirEffects) != 0 {
					t.Fatalf("non-final rmdir emitted effects: %#v", rmdirEffects)
				}

				scanEffects := handleEngineInput(state, commandReconcileCgroupLiveness{
					ScanStartedAt: time.Now().UTC().Add(time.Second),
					CheckedAt:     time.Now().UTC().Add(2 * time.Second),
					LiveCgroupIDs: map[uint64]struct{}{84: {}},
				})
				if len(scanEffects) != 0 {
					t.Fatalf("scan after non-final rmdir emitted effects: %#v", scanEffects)
				}
				if got := len(state.removedCgroupQueue); got != 1 {
					t.Fatalf("removed cgroup queue length = %d, want 1", got)
				}
				if state.cgroupsByJob[jobID][42].State != trackedCgroupRemoved {
					t.Fatalf("rmdir cgroup state = %v, want removed", state.cgroupsByJob[jobID][42].State)
				}
				if state.cgroupsByJob[jobID][84].State != trackedCgroupActive {
					t.Fatalf("live cgroup state = %v, want active", state.cgroupsByJob[jobID][84].State)
				}
			},
		},
		{
			name: "cgroup rmdir then liveness scan can drain remaining active cgroup",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42, 84)
				rmdirEffects := handleEngineInput(state, cgroupRmdirSample{CgroupID: 42})
				if len(rmdirEffects) != 0 {
					t.Fatalf("non-final rmdir emitted effects: %#v", rmdirEffects)
				}

				scanEffects := handleEngineInput(state, commandReconcileCgroupLiveness{
					ScanStartedAt: time.Now().UTC().Add(time.Second),
					CheckedAt:     time.Now().UTC().Add(2 * time.Second),
					LiveCgroupIDs: map[uint64]struct{}{},
				})
				if !hasNotifyJobEndedEffect(scanEffects) {
					t.Fatalf("expected scan to notify when remaining active cgroup is missing")
				}
				assertEffectOrder(t, scanEffects,
					notifyJobEnded{},
				)
				if got := len(state.removedCgroupQueue); got != 2 {
					t.Fatalf("removed cgroup queue length = %d, want 2", got)
				}
			},
		},
		{
			name: "cgroup liveness scan then rmdir can drain remaining active cgroup",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42, 84)
				scanEffects := handleEngineInput(state, commandReconcileCgroupLiveness{
					ScanStartedAt: time.Now().UTC().Add(time.Second),
					CheckedAt:     time.Now().UTC().Add(2 * time.Second),
					LiveCgroupIDs: map[uint64]struct{}{84: {}},
				})
				if len(scanEffects) != 0 {
					t.Fatalf("non-final scan emitted effects: %#v", scanEffects)
				}

				rmdirEffects := handleEngineInput(state, cgroupRmdirSample{CgroupID: 84})
				if !hasNotifyJobEndedEffect(rmdirEffects) {
					t.Fatalf("expected rmdir to notify when remaining active cgroup is removed")
				}
				assertEffectOrder(t, rmdirEffects,
					notifyJobEnded{},
				)
				if got := len(state.removedCgroupQueue); got != 2 {
					t.Fatalf("removed cgroup queue length = %d, want 2", got)
				}
			},
		},
		{
			name: "cgroup liveness scan after final rmdir does not notify twice",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42)
				rmdirEffects := handleEngineInput(state, cgroupRmdirSample{CgroupID: 42})
				if !hasNotifyJobEndedEffect(rmdirEffects) {
					t.Fatalf("expected rmdir to notify when final active cgroup is removed")
				}

				scanEffects := handleEngineInput(state, commandReconcileCgroupLiveness{
					ScanStartedAt: time.Now().UTC().Add(time.Second),
					CheckedAt:     time.Now().UTC().Add(2 * time.Second),
					LiveCgroupIDs: map[uint64]struct{}{},
				})
				if len(scanEffects) != 0 {
					t.Fatalf("scan after final rmdir emitted effects: %#v", scanEffects)
				}
				if got := len(state.removedCgroupQueue); got != 1 {
					t.Fatalf("removed cgroup queue length = %d, want 1", got)
				}
			},
		},
		{
			name: "exit marks process as logically deleted",
			run: func(t *testing.T) {
				state := destinationTrackedState(jobID, 42)
				parentIdentity := processIdentity{PID: 100, StartBoottime: 1}
				childIdentity := processIdentity{PID: 101, StartBoottime: 2}
				state.recordExec(jobID, parentIdentity, "/usr/bin/bash", nil, 0)

				handleEngineInput(state, forkSample{
					Child:         childIdentity,
					Parent:        parentIdentity,
					ChildCgroupID: 42,
				})
				handleEngineInput(state, exitSample{Identity: childIdentity, CgroupID: 42})

				if !testProcessExists(state, jobID, childIdentity) {
					t.Fatal("child process node missing after exit")
				}
				if !testProcessIsExited(state, jobID, childIdentity) {
					t.Fatalf("child process must be retained as exited")
				}
				if got := testExitedProcessCount(state, jobID); got != 1 {
					t.Fatalf("exited process count = %d, want 1", got)
				}
			},
		},
		{
			name: "reply register job is emitted once",
			run: func(t *testing.T) {
				state := newJobTrackingState()
				effects := handleEngineInput(state, commandRegisterJob{
					JobID: jobID,
					Reply: make(chan registerJobReply, 1),
				})

				assertReplyCount(t, effects, 1)
			},
		},
		{
			name: "job event channel lifecycle matches job lifecycle",
			run: func(t *testing.T) {
				state := newJobTrackingState()
				handleEngineInput(state, commandRegisterJob{
					JobID: jobID,
					Reply: make(chan registerJobReply, 1),
				})

				if _, registered := state.jobs[jobID]; !registered {
					t.Fatalf("job missing after set")
				}
				if _, ok := state.jobEventChannels[jobID]; !ok {
					t.Fatalf("event channel missing after set")
				}

				effects := handleEngineInput(state, commandRemoveJob{JobID: jobID})
				runTestEffects(t, state, effects)
				if _, registered := state.jobs[jobID]; registered {
					t.Fatalf("job still present after remove")
				}
				if _, ok := state.jobEventChannels[jobID]; ok {
					t.Fatalf("event channel still present after remove")
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, test.run)
	}
}

func TestKernelTrackerRun_LogsCgroupAttachOwnerConflict(t *testing.T) {
	sourceJobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	destinationJobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "456")
	logs := &lockedBuffer{}
	engine := newTestKernelTracker(slog.New(slog.NewJSONHandler(logs, nil)), nil, noopKernelIO{}, "")
	engine.jobTracking.registerJob(sourceJobID, defaultEventRecordBufferSize)
	engine.jobTracking.bind(sourceJobID, 42)
	engine.jobTracking.registerJob(destinationJobID, defaultEventRecordBufferSize)
	engine.jobTracking.bind(destinationJobID, 84)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()

	engine.inputCh <- cgroupAttachSample{
		Tgid:                100,
		SourceCgroupID:      42,
		DestinationCgroupID: 84,
	}

	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if strings.Contains(logs.String(), "bpf_cgroup_attach_owner_conflict") {
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("Run error = %v, want nil", err)
			}
			return
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("owner conflict was not logged: %s", logs.String())
		case <-ticker.C:
		}
	}
}
