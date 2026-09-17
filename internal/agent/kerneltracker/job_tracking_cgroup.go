package kerneltracker

import (
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

type trackedCgroupState uint8

const (
	trackedCgroupActive trackedCgroupState = iota
	trackedCgroupRemoved
)

const cgroupRemovalGracePeriod = processExitGracePeriod

type trackedCgroup struct {
	State trackedCgroupState
	// TrackedAt is compared with async liveness scan start time. A cgroup
	// first tracked after a scan started must not be removed by that scan's
	// stale live-ID snapshot.
	TrackedAt time.Time
	RemovedAt time.Time
}

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

type cgroupPurgeCandidate struct {
	JobID    jobcontext.JobIdentity
	CgroupID uint64
}

// bind mirrors a cgroup -> Job attribution already accepted by KernelIO/eBPF.
// It is non-overwriting so one cgroup cannot silently move between Jobs.
func (s *jobTrackingState) bind(jobID jobcontext.JobIdentity, cgroupID uint64) bool {
	return s.bindAt(jobID, cgroupID, time.Now().UTC())
}

// bindAt records when this userspace mirror first accepted the cgroup. Tests
// and async reconciliation pass explicit times to make scan-race behavior clear.
func (s *jobTrackingState) bindAt(jobID jobcontext.JobIdentity, cgroupID uint64, trackedAt time.Time) bool {
	if owner, ok := s.jobByCgroup[cgroupID]; ok {
		// Removed cgroups stay attributable during their grace period, but
		// rmdir is a one-way lifecycle signal. Do not reactivate them.
		return owner == jobID
	}
	s.jobByCgroup[cgroupID] = jobID
	if s.cgroupsByJob[jobID] == nil {
		s.cgroupsByJob[jobID] = make(map[uint64]*trackedCgroup)
	}
	cgroup := s.cgroupsByJob[jobID][cgroupID]
	if cgroup == nil {
		cgroup = &trackedCgroup{}
		s.cgroupsByJob[jobID][cgroupID] = cgroup
	}
	cgroup.State = trackedCgroupActive
	cgroup.TrackedAt = trackedAt
	cgroup.RemovedAt = time.Time{}
	return true
}

// unbind removes one cgroup attribution but leaves the per-Job reverse entry
// for RemoveJob cleanup.
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

func (s *jobTrackingState) markTrackedCgroupRemoved(cgroupID uint64, now time.Time) cgroupDetachResult {
	jobID, ok := s.jobForCgroup(cgroupID)
	if !ok {
		return cgroupDetachResult{}
	}

	cgroup := s.cgroupsByJob[jobID][cgroupID]
	if cgroup == nil {
		return cgroupDetachResult{}
	}
	if cgroup.State == trackedCgroupRemoved {
		return cgroupDetachResult{JobID: jobID, Found: true}
	}

	cgroup.State = trackedCgroupRemoved
	cgroup.RemovedAt = now
	// cgroup_rmdir is the primary deletion signal. Periodic liveness
	// reconciliation only uses this same path to compensate for a missed
	// rmdir sample; it does not delete cgroups immediately. Keep the forward
	// cgroup -> Job mapping until purge so late samples from the removed
	// cgroup still resolve to the Job.
	s.removedCgroupQueue = append(s.removedCgroupQueue, cgroupPurgeCandidate{JobID: jobID, CgroupID: cgroupID})
	return cgroupDetachResult{
		JobID:      jobID,
		Found:      true,
		JobDrained: s.activeCgroupCount(jobID) == 0,
	}
}

// reconcileCgroupLiveness applies a filesystem scan result to loop-owned state.
// The scan is a safety net for missed cgroup_rmdir samples: it detects active
// tracked cgroups that no longer exist, then moves them into the same
// removed-pending queue used by the rmdir handler. The scan itself runs outside
// the engine loop; this method is the only place that interprets the live-ID
// snapshot and mutates tracked cgroup ownership.
func (s *jobTrackingState) reconcileCgroupLiveness(liveCgroupIDs map[uint64]struct{}, scanStartedAt time.Time, checkedAt time.Time) []cgroupDetachResult {
	var removed []cgroupDetachResult
	for _, cgroups := range s.cgroupsByJob {
		for cgroupID, cgroup := range cgroups {
			if cgroup == nil || cgroup.State != trackedCgroupActive {
				continue
			}
			if cgroup.TrackedAt.After(scanStartedAt) {
				continue
			}
			if _, ok := liveCgroupIDs[cgroupID]; ok {
				continue
			}
			result := s.markTrackedCgroupRemoved(cgroupID, checkedAt)
			if result.Found {
				removed = append(removed, result)
			}
		}
	}
	return removed
}

func (s *jobTrackingState) activeCgroupCount(jobID jobcontext.JobIdentity) int {
	count := 0
	for _, cgroup := range s.cgroupsByJob[jobID] {
		if cgroup != nil && cgroup.State == trackedCgroupActive {
			count++
		}
	}
	return count
}

func (s *jobTrackingState) expiredRemovedCgroups(now time.Time) []cgroupPurgeCandidate {
	var out []cgroupPurgeCandidate
	// Like exited processes, removed cgroups are queued in removal order.
	// Stop at the first non-expired entry so later entries wait their turn.
	for _, candidate := range s.removedCgroupQueue {
		cgroup := s.cgroupsByJob[candidate.JobID][candidate.CgroupID]
		if cgroup == nil || cgroup.State != trackedCgroupRemoved {
			break
		}
		if cgroup.RemovedAt.Add(cgroupRemovalGracePeriod).After(now) {
			break
		}
		out = append(out, candidate)
	}
	return out
}

func (s *jobTrackingState) purgeRemovedCgroups(candidates []cgroupPurgeCandidate) {
	if len(candidates) == 0 {
		return
	}
	for _, candidate := range candidates {
		jobID, ok := s.jobForCgroup(candidate.CgroupID)
		if !ok || jobID != candidate.JobID {
			continue
		}
		cgroup := s.cgroupsByJob[jobID][candidate.CgroupID]
		if cgroup == nil || cgroup.State != trackedCgroupRemoved {
			continue
		}
		s.unbind(jobID, candidate.CgroupID)
	}
	if len(candidates) >= len(s.removedCgroupQueue) {
		s.removedCgroupQueue = nil
	} else {
		s.removedCgroupQueue = s.removedCgroupQueue[len(candidates):]
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
	// RemoveJob cleans active and removed-pending cgroups together, so any
	// queued lazy-deletion entries for this Job must be discarded here.
	kept := s.removedCgroupQueue[:0]
	for _, candidate := range s.removedCgroupQueue {
		if candidate.JobID == jobID {
			continue
		}
		kept = append(kept, candidate)
	}
	s.removedCgroupQueue = kept
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
