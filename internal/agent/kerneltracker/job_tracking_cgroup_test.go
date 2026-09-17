package kerneltracker

import (
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestJobTrackingState_BindAndJobForCgroup(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	jobID := newJob("100")
	trackedAt := time.Unix(100, 0)

	if !s.bindAt(jobID, 42, trackedAt) {
		t.Fatalf("Bind on empty state must succeed")
	}

	owner, ok := s.jobForCgroup(42)
	if !ok || owner != jobID {
		t.Fatalf("JobForCgroup: got owner=%v ok=%v, want %v true", owner, ok, jobID)
	}
	if !testHasTrackedCgroups(s, jobID) {
		t.Fatal("tracked cgroups must be present after Bind")
	}
	if got := s.cgroupsByJob[jobID][42].TrackedAt; !got.Equal(trackedAt) {
		t.Fatalf("tracked at = %v, want %v", got, trackedAt)
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

	first := s.bind(jobID, 42)
	second := s.bind(jobID, 42)
	if !first || !second {
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

func TestJobTrackingState_MarkTrackedCgroupRemoved(t *testing.T) {
	t.Parallel()

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		got := s.markTrackedCgroupRemoved(42, time.Unix(100, 0))
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

		got := s.markTrackedCgroupRemoved(42, time.Unix(100, 0))
		if !got.Found || got.JobID != jobID || got.JobDrained {
			t.Fatalf("partial remove result = %+v, want found/not drained for %v", got, jobID)
		}
		if owner, ok := s.jobForCgroup(42); !ok || owner != jobID {
			t.Fatalf("removed pending cgroup owner = %v ok=%v, want %v true", owner, ok, jobID)
		}
		if owner, ok := s.jobForCgroup(84); !ok || owner != jobID {
			t.Fatalf("remaining cgroup owner = %v ok=%v, want %v true", owner, ok, jobID)
		}
		if state := s.cgroupsByJob[jobID][42].State; state != trackedCgroupRemoved {
			t.Fatalf("removed cgroup state = %v, want removed", state)
		}
	})

	t.Run("drained after last cgroup", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bind(jobID, 42)

		got := s.markTrackedCgroupRemoved(42, time.Unix(100, 0))
		if !got.Found || got.JobID != jobID || !got.JobDrained {
			t.Fatalf("last remove result = %+v, want found/drained for %v", got, jobID)
		}
		if owner, ok := s.jobForCgroup(42); !ok || owner != jobID {
			t.Fatalf("removed pending cgroup owner = %v ok=%v, want %v true", owner, ok, jobID)
		}
		if _, ok := s.cgroupsByJob[jobID]; !ok {
			t.Fatal("empty reverse index should remain until RemoveJob cleanup")
		}
	})

	t.Run("duplicate rmdir is idempotent", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bind(jobID, 42)

		first := s.markTrackedCgroupRemoved(42, time.Unix(100, 0))
		second := s.markTrackedCgroupRemoved(42, time.Unix(200, 0))
		if !first.JobDrained {
			t.Fatalf("first remove result = %+v, want drained", first)
		}
		if second.JobDrained {
			t.Fatalf("duplicate remove result = %+v, want not drained", second)
		}
		if got := s.cgroupsByJob[jobID][42].RemovedAt; !got.Equal(time.Unix(100, 0)) {
			t.Fatalf("duplicate rmdir changed removed timestamp: got %v", got)
		}
		if got := len(s.removedCgroupQueue); got != 1 {
			t.Fatalf("removed cgroup queue length = %d, want 1", got)
		}
	})
}

func TestJobTrackingState_PurgeRemovedCgroups(t *testing.T) {
	t.Parallel()

	now := time.Unix(200, 0)
	t.Run("grace period retains removed cgroup", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bind(jobID, 42)
		s.markTrackedCgroupRemoved(42, now.Add(-cgroupRemovalGracePeriod+time.Second))

		if got := s.expiredRemovedCgroups(now); len(got) != 0 {
			t.Fatalf("expired removed cgroups before grace = %#v, want none", got)
		}
	})

	t.Run("expired cgroup is purge candidate", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bind(jobID, 42)
		s.markTrackedCgroupRemoved(42, now.Add(-cgroupRemovalGracePeriod-time.Second))

		got := s.expiredRemovedCgroups(now)
		want := []cgroupPurgeCandidate{{JobID: jobID, CgroupID: 42}}
		if len(got) != len(want) || got[0] != want[0] {
			t.Fatalf("expired removed cgroups = %#v, want %#v", got, want)
		}
	})

	t.Run("purge removes only removed cgroups", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bind(jobID, 42)
		s.bind(jobID, 84)
		s.markTrackedCgroupRemoved(42, now)

		s.purgeRemovedCgroups([]cgroupPurgeCandidate{{JobID: jobID, CgroupID: 42}})
		if _, ok := s.jobForCgroup(42); ok {
			t.Fatal("purged removed cgroup still has owner")
		}
		if owner, ok := s.jobForCgroup(84); !ok || owner != jobID {
			t.Fatalf("active cgroup owner = %v ok=%v, want %v true", owner, ok, jobID)
		}
		if got := len(s.removedCgroupQueue); got != 0 {
			t.Fatalf("removed cgroup queue length after purge = %d, want 0", got)
		}
	})

	t.Run("queue stops at first non-expired removed cgroup", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bind(jobID, 42)
		s.bind(jobID, 84)
		s.markTrackedCgroupRemoved(42, now.Add(-cgroupRemovalGracePeriod+time.Second))
		s.markTrackedCgroupRemoved(84, now.Add(-cgroupRemovalGracePeriod-time.Second))

		if got := s.expiredRemovedCgroups(now); len(got) != 0 {
			t.Fatalf("expired removed cgroups behind non-expired head = %#v, want none", got)
		}
	})
}

func TestJobTrackingState_BindDoesNotReactivateSameJobRemovedCgroup(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	jobID := newJob("100")
	s.bind(jobID, 42)
	s.markTrackedCgroupRemoved(42, time.Unix(100, 0))

	if !s.bind(jobID, 42) {
		t.Fatal("same-job bind of removed cgroup must succeed")
	}
	cgroup := s.cgroupsByJob[jobID][42]
	if cgroup.State != trackedCgroupRemoved {
		t.Fatalf("same-job bind cgroup state = %v, want removed", cgroup.State)
	}
	if got := cgroup.RemovedAt; !got.Equal(time.Unix(100, 0)) {
		t.Fatalf("same-job bind changed removed timestamp: got %v", got)
	}
	if got := len(s.removedCgroupQueue); got != 1 {
		t.Fatalf("removed cgroup queue length = %d, want 1", got)
	}
}

func TestJobTrackingState_ReconcileCgroupLiveness(t *testing.T) {
	t.Parallel()

	scanStartedAt := time.Unix(200, 0)
	checkedAt := time.Unix(210, 0)

	t.Run("live active cgroup remains active", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bindAt(jobID, 42, scanStartedAt.Add(-time.Second))

		removed := s.reconcileCgroupLiveness(map[uint64]struct{}{42: {}}, scanStartedAt, checkedAt)
		if len(removed) != 0 {
			t.Fatalf("removed cgroups = %#v, want none", removed)
		}
		if state := s.cgroupsByJob[jobID][42].State; state != trackedCgroupActive {
			t.Fatalf("cgroup state = %v, want active", state)
		}
	})

	t.Run("missing non-final cgroup becomes removed pending", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bindAt(jobID, 42, scanStartedAt.Add(-time.Second))
		s.bindAt(jobID, 84, scanStartedAt.Add(-time.Second))

		removed := s.reconcileCgroupLiveness(map[uint64]struct{}{84: {}}, scanStartedAt, checkedAt)
		if len(removed) != 1 || removed[0].JobID != jobID || removed[0].JobDrained {
			t.Fatalf("removed result = %#v, want one non-drained result for %v", removed, jobID)
		}
		if state := s.cgroupsByJob[jobID][42].State; state != trackedCgroupRemoved {
			t.Fatalf("missing cgroup state = %v, want removed", state)
		}
		if got := s.cgroupsByJob[jobID][42].RemovedAt; !got.Equal(checkedAt) {
			t.Fatalf("removed at = %v, want %v", got, checkedAt)
		}
		if owner, ok := s.jobForCgroup(42); !ok || owner != jobID {
			t.Fatalf("removed pending owner = %v ok=%v, want %v true", owner, ok, jobID)
		}
	})

	t.Run("missing final active cgroup drains job", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bindAt(jobID, 42, scanStartedAt.Add(-time.Second))

		removed := s.reconcileCgroupLiveness(nil, scanStartedAt, checkedAt)
		if len(removed) != 1 || removed[0].JobID != jobID || !removed[0].JobDrained {
			t.Fatalf("removed result = %#v, want one drained result for %v", removed, jobID)
		}
	})

	t.Run("all active cgroups missing drains once", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bindAt(jobID, 42, scanStartedAt.Add(-time.Second))
		s.bindAt(jobID, 84, scanStartedAt.Add(-time.Second))

		removed := s.reconcileCgroupLiveness(nil, scanStartedAt, checkedAt)
		if len(removed) != 2 {
			t.Fatalf("removed result count = %d, want 2: %#v", len(removed), removed)
		}
		drained := 0
		for _, result := range removed {
			if result.JobID != jobID {
				t.Fatalf("removed result job = %v, want %v", result.JobID, jobID)
			}
			if result.JobDrained {
				drained++
			}
		}
		if drained != 1 {
			t.Fatalf("drained result count = %d, want 1: %#v", drained, removed)
		}
	})

	t.Run("removed pending cgroup is ignored", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bindAt(jobID, 42, scanStartedAt.Add(-time.Second))
		s.markTrackedCgroupRemoved(42, checkedAt.Add(-time.Second))

		removed := s.reconcileCgroupLiveness(nil, scanStartedAt, checkedAt)
		if len(removed) != 0 {
			t.Fatalf("removed result = %#v, want none", removed)
		}
		if got := len(s.removedCgroupQueue); got != 1 {
			t.Fatalf("removed cgroup queue length = %d, want 1", got)
		}
	})

	t.Run("cgroup tracked after scan start is skipped", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bindAt(jobID, 42, scanStartedAt.Add(time.Second))

		removed := s.reconcileCgroupLiveness(nil, scanStartedAt, checkedAt)
		if len(removed) != 0 {
			t.Fatalf("removed result = %#v, want none", removed)
		}
		if state := s.cgroupsByJob[jobID][42].State; state != trackedCgroupActive {
			t.Fatalf("new cgroup state = %v, want active", state)
		}
	})

	t.Run("stale scan after remove job is no-op", func(t *testing.T) {
		t.Parallel()

		s := newJobTrackingState()
		jobID := newJob("100")
		s.bindAt(jobID, 42, scanStartedAt.Add(-time.Second))
		s.removeJob(jobID)

		removed := s.reconcileCgroupLiveness(nil, scanStartedAt, checkedAt)
		if len(removed) != 0 {
			t.Fatalf("removed result = %#v, want none", removed)
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

	first := s.putStaging("docker-aaaa.scope", jobID)
	second := s.putStaging("docker-aaaa.scope", jobID)
	if !first || !second {
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
