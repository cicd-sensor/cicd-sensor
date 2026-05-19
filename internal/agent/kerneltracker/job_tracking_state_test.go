package kerneltracker

import (
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"testing"
)

func TestJobTrackingState_RemoveJobClearsAllJobOwnedState(t *testing.T) {
	t.Parallel()

	s := newJobTrackingState()
	target := newJob("100")
	other := newJob("200")
	targetProcess := processIdentity{PID: 10, StartBoottime: 1000}
	otherProcess := processIdentity{PID: 20, StartBoottime: 2000}

	s.registerJob(target, 1)
	s.bind(target, 42)
	s.putStaging("docker-target.scope", target)
	s.jobEventDropCounts[target] = 3
	s.recordExec(target, targetProcess, "/bin/target", nil, 0)

	s.registerJob(other, 1)
	s.bind(other, 84)
	s.putStaging("docker-other.scope", other)
	s.jobEventDropCounts[other] = 5
	s.recordExec(other, otherProcess, "/bin/other", nil, 0)

	channel := s.removeJob(target)
	if channel == nil {
		t.Fatal("RemoveJob should return target event channel")
	}

	if _, ok := s.jobs[target]; ok {
		t.Fatal("target job registration survived RemoveJob")
	}
	if _, ok := s.jobEventChannels[target]; ok {
		t.Fatal("target event channel survived RemoveJob")
	}
	if _, ok := s.jobEventDropCounts[target]; ok {
		t.Fatal("target event drop count survived RemoveJob")
	}
	if _, ok := s.jobForCgroup(42); ok {
		t.Fatal("target cgroup forward index survived RemoveJob")
	}
	if _, ok := s.cgroupsByJob[target]; ok {
		t.Fatal("target cgroup reverse index survived RemoveJob")
	}
	if _, ok := s.stagingByBasename["docker-target.scope"]; ok {
		t.Fatal("target staging forward index survived RemoveJob")
	}
	if _, ok := s.stagingByJob[target]; ok {
		t.Fatal("target staging reverse index survived RemoveJob")
	}
	if _, ok := s.processesByJob[target]; ok {
		t.Fatal("target process state survived RemoveJob")
	}

	if _, ok := s.jobs[other]; !ok {
		t.Fatal("bystander job registration was removed")
	}
	if _, ok := s.jobEventChannels[other]; !ok {
		t.Fatal("bystander event channel was removed")
	}
	if got := s.jobEventDropCounts[other]; got != 5 {
		t.Fatalf("bystander event drop count = %d, want 5", got)
	}
	if owner, ok := s.jobForCgroup(84); !ok || owner != other {
		t.Fatalf("bystander cgroup owner = %v ok=%v, want %v true", owner, ok, other)
	}
	if owner, ok := s.stagingByBasename["docker-other.scope"]; !ok || owner != other {
		t.Fatalf("bystander staging owner = %v ok=%v, want %v true", owner, ok, other)
	}
	if !testProcessExists(s, other, otherProcess) {
		t.Fatal("bystander process state was removed")
	}
}

func TestJobTrackingState_RemoveJob(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		seed        func(*jobTrackingState, jobcontext.JobIdentity)
		assertEmpty bool
	}{
		{
			name: "cgroups only",
			seed: func(s *jobTrackingState, jobID jobcontext.JobIdentity) {
				s.bind(jobID, 42)
				s.bind(jobID, 84)
			},
		},
		{
			name: "staging only",
			seed: func(s *jobTrackingState, jobID jobcontext.JobIdentity) {
				s.putStaging("docker-aaaa.scope", jobID)
				s.putStaging("docker-bbbb.scope", jobID)
			},
		},
		{
			name: "cgroups and staging",
			seed: func(s *jobTrackingState, jobID jobcontext.JobIdentity) {
				s.bind(jobID, 42)
				s.putStaging("docker-aaaa.scope", jobID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newJobTrackingState()
			target := newJob("100")
			other := newJob("999")

			tc.seed(s, target)
			// Bystander job to confirm RemoveJob does not touch unrelated state.
			s.bind(other, 7)
			s.putStaging("docker-other.scope", other)

			s.removeJob(target)

			if testHasTrackedCgroups(s, target) {
				t.Errorf("tracked cgroups must be gone after RemoveJob")
			}
			if _, ok := s.jobForCgroup(42); ok {
				t.Errorf("JobForCgroup(42) must be false after RemoveJob")
			}
			if _, ok := s.jobForCgroup(84); ok {
				t.Errorf("JobForCgroup(84) must be false after RemoveJob")
			}
			if _, ok := s.stagingByBasename["docker-aaaa.scope"]; ok {
				t.Errorf("target staging entry survived RemoveJob")
			}
			if _, ok := s.stagingByBasename["docker-bbbb.scope"]; ok {
				t.Errorf("second staging basename survived RemoveJob")
			}

			// Bystander must be untouched.
			if owner, ok := s.jobForCgroup(7); !ok || owner != other {
				t.Errorf("bystander cgroup binding lost: got %v ok=%v", owner, ok)
			}
			if owner, ok := s.stagingByBasename["docker-other.scope"]; !ok || owner != other {
				t.Errorf("bystander staging entry lost: got %v ok=%v", owner, ok)
			}
		})
	}
}
