package kerneltracker

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestHandleCgroupMkdir_StagingMatchedEventBindsCgroup(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.putStaging("docker-cafef00d.scope", jobID)

	effects := handleEngineInput(state, cgroupMkdirSample{
		CgroupID:       9001,
		ParentCgroupID: 0,
		CgroupPath:     "/system.slice/docker-cafef00d.scope",
		StagingMatched: true,
	})

	if owner, ok := state.jobForCgroup(9001); !ok || owner != jobID {
		t.Fatalf("staged child cgroup was not bound: JobForCgroup(9001)=%+v ok=%v", owner, ok)
	}
	if !testHasTrackedCgroups(state, jobID) {
		t.Fatalf("tracking is missing the job after promotion")
	}
	if _, ok := state.stagingByBasename["docker-cafef00d.scope"]; ok {
		t.Fatalf("staging entry survived promotion")
	}
	if len(effects) != 0 {
		t.Fatalf("staging match should not emit effects after BPF-side tracking: %#v", effects)
	}
}

func TestHandleCgroupMkdir_NoStagingMatchIgnoresStaging(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newJobTrackingState()
	state.putStaging("docker-cafef00d.scope", jobID)

	effects := handleEngineInput(state, cgroupMkdirSample{
		CgroupID:       9002,
		ParentCgroupID: 0,
		CgroupPath:     "/system.slice/docker-cafef00d.scope",
		StagingMatched: false,
	})

	if _, ok := state.jobForCgroup(9002); ok {
		t.Fatalf("unmatched mkdir unexpectedly bound child cgroup")
	}
	if _, ok := state.stagingByBasename["docker-cafef00d.scope"]; !ok {
		t.Fatalf("staging entry was disturbed by unmatched sample")
	}
	if len(effects) != 0 {
		t.Fatalf("unmatched untracked mkdir emitted effects: %#v", effects)
	}
}

func TestHandleCgroupMkdir_StagingMatchedEventWithoutStagingEntryIsNoop(t *testing.T) {
	t.Parallel()

	state := newJobTrackingState()

	effects := handleEngineInput(state, cgroupMkdirSample{
		CgroupID:       9003,
		ParentCgroupID: 0,
		CgroupPath:     "/system.slice/docker-unknown.scope",
		StagingMatched: true,
	})

	if _, ok := state.jobForCgroup(9003); ok {
		t.Fatalf("staging-matched sample without staging mirror unexpectedly bound child cgroup")
	}
	if len(effects) != 0 {
		t.Fatalf("staging-matched-but-unmapped mkdir emitted effects: %#v", effects)
	}
}

func TestRemoveJobTracking_SweepsStaging(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	state := newTrackedState(jobID, 42)
	state.putStaging("docker-aaaa.scope", jobID)
	state.putStaging("docker-bbbb.scope", jobID)

	effects := handleEngineInput(state, commandRemoveJob{JobID: jobID})
	runTestEffects(t, state, effects)

	if _, ok := state.stagingByBasename["docker-aaaa.scope"]; ok {
		t.Fatalf("docker-aaaa.scope survived job removal")
	}
	if _, ok := state.stagingByBasename["docker-bbbb.scope"]; ok {
		t.Fatalf("docker-bbbb.scope survived job removal")
	}
	if len(state.stagingByBasename) != 0 {
		t.Fatalf("stagingByBasename should be empty after job removal; got %d", len(state.stagingByBasename))
	}
}
