package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/jobcontext"

// cgroupAttachOwnership snapshots both sides of an attach before the handler
// decides whether to emit a signal or extend the userspace mirror.
type cgroupAttachOwnership struct {
	SourceJobID      jobcontext.JobIdentity
	SourceFound      bool
	DestinationJobID jobcontext.JobIdentity
	DestinationFound bool
}

// cgroupDetachResult lets rmdir handling avoid peeking into reverse indexes.
type cgroupDetachResult struct {
	JobID      jobcontext.JobIdentity
	Found      bool
	JobDrained bool
}

// bind mirrors a cgroup -> Job attribution already accepted by KernelIO/eBPF.
// It is non-overwriting so one cgroup cannot silently move between Jobs.
func (s *jobTrackingState) bind(jobID jobcontext.JobIdentity, cgroupID uint64) bool {
	if owner, ok := s.jobByCgroup[cgroupID]; ok && owner != jobID {
		return false
	}
	s.jobByCgroup[cgroupID] = jobID
	if s.cgroupsByJob[jobID] == nil {
		s.cgroupsByJob[jobID] = make(map[uint64]struct{})
	}
	s.cgroupsByJob[jobID][cgroupID] = struct{}{}
	return true
}

// unbind removes one cgroup attribution but leaves the per-Job reverse entry
// for RemoveJob cleanup; callers can use removeTrackedCgroup for drain checks.
func (s *jobTrackingState) unbind(jobID jobcontext.JobIdentity, cgroupID uint64) {
	delete(s.jobByCgroup, cgroupID)
	if cgroups := s.cgroupsByJob[jobID]; cgroups != nil {
		delete(cgroups, cgroupID)
	}
}

// jobForCgroup is the userspace attribution lookup for flat kernel map entries.
func (s *jobTrackingState) jobForCgroup(cgroupID uint64) (jobcontext.JobIdentity, bool) {
	jobID, ok := s.jobByCgroup[cgroupID]
	return jobID, ok
}

// lookupCgroupAttachOwnership keeps attach handlers focused on case handling
// instead of exposing the forward cgroup attribution map.
func (s *jobTrackingState) lookupCgroupAttachOwnership(sourceID, destinationID uint64) cgroupAttachOwnership {
	sourceJobID, sourceFound := s.jobForCgroup(sourceID)
	destinationJobID, destinationFound := s.jobForCgroup(destinationID)
	return cgroupAttachOwnership{
		SourceJobID:      sourceJobID,
		SourceFound:      sourceFound,
		DestinationJobID: destinationJobID,
		DestinationFound: destinationFound,
	}
}

// removeTrackedCgroup applies an rmdir mirror update and reports whether the
// Job has no tracked cgroups left, without making the handler inspect indexes.
func (s *jobTrackingState) removeTrackedCgroup(cgroupID uint64) cgroupDetachResult {
	jobID, ok := s.jobForCgroup(cgroupID)
	if !ok {
		return cgroupDetachResult{}
	}

	s.unbind(jobID, cgroupID)
	return cgroupDetachResult{
		JobID:      jobID,
		Found:      true,
		JobDrained: len(s.cgroupsByJob[jobID]) == 0,
	}
}

// putStaging mirrors a basename inserted into staging_map by KernelIO.
// Cross-Job basename conflicts are rejected before kernel state is changed.
func (s *jobTrackingState) putStaging(basename string, jobID jobcontext.JobIdentity) bool {
	if owner, ok := s.stagingByBasename[basename]; ok && owner != jobID {
		return false
	}
	s.stagingByBasename[basename] = jobID
	if s.stagingByJob[jobID] == nil {
		s.stagingByJob[jobID] = make(map[string]struct{})
	}
	s.stagingByJob[jobID][basename] = struct{}{}
	return true
}

// removeStaging mirrors a kernel-side staging delete while preserving the
// empty reverse entry until RemoveJob owns whole-Job cleanup.
func (s *jobTrackingState) removeStaging(basename string, jobID jobcontext.JobIdentity) bool {
	if owner, ok := s.stagingByBasename[basename]; !ok || owner != jobID {
		return false
	}
	delete(s.stagingByBasename, basename)
	if owned := s.stagingByJob[jobID]; owned != nil {
		delete(owned, basename)
	}
	return true
}

// promoteStagedCgroup consumes a userspace staging mirror after the kernel
// matched staging_map and started tracking the new cgroup.
func (s *jobTrackingState) promoteStagedCgroup(basename string, cgroupID uint64) (jobcontext.JobIdentity, bool) {
	jobID, ok := s.stagingByBasename[basename]
	if !ok {
		return jobcontext.JobIdentity{}, false
	}
	if !s.bind(jobID, cgroupID) {
		return jobcontext.JobIdentity{}, false
	}
	s.removeStaging(basename, jobID)
	return jobID, true
}

// removeCgroupAndStaging is the userspace half of RemoveJob cleanup after
// KernelIO has deleted the Job's remaining flat map entries.
func (s *jobTrackingState) removeCgroupAndStaging(jobID jobcontext.JobIdentity) {
	for cgroupID := range s.cgroupsByJob[jobID] {
		delete(s.jobByCgroup, cgroupID)
	}
	for basename := range s.stagingByJob[jobID] {
		delete(s.stagingByBasename, basename)
	}
	delete(s.cgroupsByJob, jobID)
	delete(s.stagingByJob, jobID)
}

// cgroupsForJob lists kernel tracked_cgroups entries that RemoveJob must clean.
func (s *jobTrackingState) cgroupsForJob(jobID jobcontext.JobIdentity) []uint64 {
	cgroups := s.cgroupsByJob[jobID]
	if len(cgroups) == 0 {
		return nil
	}
	out := make([]uint64, 0, len(cgroups))
	for cgroupID := range cgroups {
		out = append(out, cgroupID)
	}
	return out
}

// stagingForJob lists kernel staging_map entries that RemoveJob must clean.
func (s *jobTrackingState) stagingForJob(jobID jobcontext.JobIdentity) []string {
	staging := s.stagingByJob[jobID]
	if len(staging) == 0 {
		return nil
	}
	out := make([]string, 0, len(staging))
	for basename := range staging {
		out = append(out, basename)
	}
	return out
}
