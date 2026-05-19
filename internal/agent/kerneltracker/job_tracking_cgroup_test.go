package kerneltracker

import (
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"testing"
)

func TestJobTrackingState_BindAndJobForCgroup(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	jobID := newJob("100")

	if !s.bind(jobID, 42) {
		t.Fatalf("Bind on empty state must succeed")
	}

	owner, ok := s.jobForCgroup(42)
	if !ok || owner != jobID {
		t.Fatalf("JobForCgroup: got owner=%v ok=%v, want %v true", owner, ok, jobID)
	}
	if !testHasTrackedCgroups(s, jobID) {
		t.Fatal("tracked cgroups must be present after Bind")
	}
}

func TestJobTrackingState_Bind_RejectsCrossJob(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	first := newJob("100")
	second := newJob("200")

	if !s.bind(first, 42) {
		t.Fatalf("first Bind must succeed")
	}
	if s.bind(second, 42) {
		t.Fatalf("second Bind on same cgroup must fail when owner differs")
	}

	owner, _ := s.jobForCgroup(42)
	if owner != first {
		t.Fatalf("owner changed after rejected Bind: got %v, want %v", owner, first)
	}
}

func TestJobTrackingState_Bind_IdempotentSameJob(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	jobID := newJob("100")

	if !s.bind(jobID, 42) || !s.bind(jobID, 42) {
		t.Fatalf("repeated Bind for same (jobID, cgroupID) must succeed")
	}
}

func TestJobTrackingState_LookupCgroupAttachOwnership(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	sourceJob := newJob("100")
	destinationJob := newJob("200")
	s.bind(sourceJob, 42)
	s.bind(destinationJob, 84)

	got := s.lookupCgroupAttachOwnership(42, 84)
	if !got.SourceFound || got.SourceJobID != sourceJob {
		t.Fatalf("source ownership = %+v, want %v found", got, sourceJob)
	}
	if !got.DestinationFound || got.DestinationJobID != destinationJob {
		t.Fatalf("destination ownership = %+v, want %v found", got, destinationJob)
	}

	missing := s.lookupCgroupAttachOwnership(1000, 2000)
	if missing.SourceFound || missing.DestinationFound {
		t.Fatalf("missing ownership = %+v, want neither side found", missing)
	}
}

func TestJobTrackingState_UnbindLeavesEmptyReverseIndexForJobCleanup(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	jobID := newJob("100")
	s.bind(jobID, 42)
	s.bind(jobID, 84)

	s.unbind(jobID, 42)
	if !testHasTrackedCgroups(s, jobID) {
		t.Fatal("tracked cgroups must remain while one cgroup remains bound")
	}

	s.unbind(jobID, 84)
	if !testHasTrackedCgroups(s, jobID) {
		t.Fatal("tracked cgroup reverse index must remain until RemoveJob cleanup")
	}
	if got := len(s.cgroupsByJob[jobID]); got != 0 {
		t.Fatalf("tracked cgroup reverse index length = %d, want 0", got)
	}
	if _, ok := s.jobForCgroup(42); ok {
		t.Fatal("JobForCgroup must return false after Unbind")
	}

	s.removeJob(jobID)
	if testHasTrackedCgroups(s, jobID) {
		t.Fatal("tracked cgroup reverse index must disappear after RemoveJob")
	}
}

func TestJobTrackingState_RemoveTrackedCgroup(t *testing.T) {
	t.Parallel()

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		got := s.removeTrackedCgroup(42)
		if got.Found || got.JobDrained || got.JobID != (jobcontext.JobIdentity{}) {
			t.Fatalf("unknown remove result = %+v, want zero value", got)
		}
	})

	t.Run("not drained while another cgroup remains", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bind(jobID, 42)
		s.bind(jobID, 84)

		got := s.removeTrackedCgroup(42)
		if !got.Found || got.JobID != jobID || got.JobDrained {
			t.Fatalf("partial remove result = %+v, want found/not drained for %v", got, jobID)
		}
		if _, ok := s.jobForCgroup(42); ok {
			t.Fatal("removed cgroup still has owner")
		}
		if owner, ok := s.jobForCgroup(84); !ok || owner != jobID {
			t.Fatalf("remaining cgroup owner = %v ok=%v, want %v true", owner, ok, jobID)
		}
	})

	t.Run("drained after last cgroup", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bind(jobID, 42)

		got := s.removeTrackedCgroup(42)
		if !got.Found || got.JobID != jobID || !got.JobDrained {
			t.Fatalf("last remove result = %+v, want found/drained for %v", got, jobID)
		}
		if _, ok := s.jobForCgroup(42); ok {
			t.Fatal("removed cgroup still has owner")
		}
		if _, ok := s.cgroupsByJob[jobID]; !ok {
			t.Fatal("empty reverse index should remain until RemoveJob cleanup")
		}
	})
}

func TestJobTrackingState_StageCgroupBasename_RejectsCrossJobOwner(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	first := newJob("100")
	second := newJob("200")

	if !s.putStaging("docker-aaaa.scope", first) {
		t.Fatal("first StageCgroupBasename must succeed")
	}
	if s.putStaging("docker-aaaa.scope", second) {
		t.Fatal("second StageCgroupBasename on same basename must fail when owner differs")
	}

	owner, ok := s.stagingByBasename["docker-aaaa.scope"]
	if !ok || owner != first {
		t.Fatalf("staging owner: got %v ok=%v, want %v true", owner, ok, first)
	}
	if _, ok := s.stagingByJob[second]["docker-aaaa.scope"]; ok {
		t.Fatal("rejected StageCgroupBasename created reverse index for second job")
	}
}

func TestJobTrackingState_StageCgroupBasename_IdempotentSameJob(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	jobID := newJob("100")

	if !s.putStaging("docker-aaaa.scope", jobID) || !s.putStaging("docker-aaaa.scope", jobID) {
		t.Fatal("repeated StageCgroupBasename for same (basename, jobID) must succeed")
	}
	if got := len(s.stagingByBasename); got != 1 {
		t.Fatalf("staging basename count: got %d, want 1", got)
	}
	if got := len(s.stagingByJob[jobID]); got != 1 {
		t.Fatalf("staging reverse index count: got %d, want 1", got)
	}
}

func TestJobTrackingState_StagingMirrorCount(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	jobID := newJob("100")

	if got := len(s.stagingByBasename); got != 0 {
		t.Fatalf("empty staging mirror count: got %d, want 0", got)
	}
	s.putStaging("a", jobID)
	s.putStaging("b", jobID)
	if got := len(s.stagingByBasename); got != 2 {
		t.Fatalf("staging mirror count after two StageCgroupBasename: got %d, want 2", got)
	}
	s.removeStaging("a", jobID)
	if got := len(s.stagingByBasename); got != 1 {
		t.Fatalf("staging mirror count after RemoveStaging: got %d, want 1", got)
	}
}

func TestJobTrackingState_RemoveStagingLeavesEmptyReverseIndexForJobCleanup(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	jobID := newJob("100")
	s.putStaging("docker-aaaa.scope", jobID)

	if !s.removeStaging("docker-aaaa.scope", jobID) {
		t.Fatal("RemoveStaging should remove owned basename")
	}
	if _, ok := s.stagingByBasename["docker-aaaa.scope"]; ok {
		t.Fatal("staging basename survived RemoveStaging")
	}
	if owned, ok := s.stagingByJob[jobID]; !ok || len(owned) != 0 {
		t.Fatalf("staging reverse index = %v ok=%v, want empty entry until RemoveJob", owned, ok)
	}

	s.removeJob(jobID)
	if _, ok := s.stagingByJob[jobID]; ok {
		t.Fatal("staging reverse index must disappear after RemoveJob")
	}
}

func TestJobTrackingState_RemoveStagingRejectsWrongOwner(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	owner := newJob("100")
	other := newJob("200")
	s.putStaging("docker-aaaa.scope", owner)

	if s.removeStaging("docker-aaaa.scope", other) {
		t.Fatal("RemoveStaging with wrong owner must fail")
	}
	if got, ok := s.stagingByBasename["docker-aaaa.scope"]; !ok || got != owner {
		t.Fatalf("wrong-owner RemoveStaging changed owner: got %v ok=%v, want %v true", got, ok, owner)
	}
	if _, ok := s.stagingByJob[owner]["docker-aaaa.scope"]; !ok {
		t.Fatal("wrong-owner RemoveStaging removed owner's reverse index")
	}
}

func TestJobTrackingState_Cgroups(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	first := newJob("100")
	second := newJob("200")
	s.bind(first, 42)
	s.bind(first, 84)
	s.bind(second, 7)

	seen := make(map[uint64]jobcontext.JobIdentity)
	for cgroupID := range s.jobByCgroup {
		if _, dup := seen[cgroupID]; dup {
			t.Fatalf("cgroupID %d returned twice", cgroupID)
		}
		jobID, ok := s.jobForCgroup(cgroupID)
		if !ok {
			t.Fatalf("JobForCgroup(%d) missing", cgroupID)
		}
		seen[cgroupID] = jobID
	}
	if len(seen) != 3 {
		t.Fatalf("Cgroups count: got %d, want 3 (state=%v)", len(seen), seen)
	}
	if seen[42] != first || seen[84] != first || seen[7] != second {
		t.Fatalf("Cgroups content mismatch: %v", seen)
	}
}

func TestJobTrackingState_StagedBasenames(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	jobID := newJob("100")
	s.putStaging("a", jobID)
	s.putStaging("b", jobID)
	s.putStaging("c", jobID)

	seen := make(map[string]struct{})
	for basename := range s.stagingByBasename {
		seen[basename] = struct{}{}
	}
	if len(seen) != 3 {
		t.Fatalf("StagedBasenames count: got %d, want 3", len(seen))
	}
	for _, want := range []string{"a", "b", "c"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("StagedBasenames did not return %q", want)
		}
	}
}
