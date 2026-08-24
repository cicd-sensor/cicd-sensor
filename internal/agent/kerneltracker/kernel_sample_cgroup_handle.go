package kerneltracker

import (
	"path/filepath"
	"time"
)

type cgroupMkdirSample struct {
	CgroupID       uint64
	ParentCgroupID uint64
	CgroupPath     string
	TsNs           uint64
	// StagingMatched is true when an untracked-parent mkdir matched staging_map.
	StagingMatched bool
}

func (cgroupMkdirSample) sealedEngineInput()         {}
func (cgroupMkdirSample) sealedDecodedKernelSample() {}

type cgroupAttachSample struct {
	Tgid                int32
	SourceCgroupID      uint64
	DestinationCgroupID uint64
	TsNs                uint64
}

func (cgroupAttachSample) sealedEngineInput()         {}
func (cgroupAttachSample) sealedDecodedKernelSample() {}

type cgroupRmdirSample struct {
	CgroupID uint64
	TsNs     uint64
}

func (cgroupRmdirSample) sealedEngineInput()         {}
func (cgroupRmdirSample) sealedDecodedKernelSample() {}

func handleCgroupMkdirSample(state *jobTrackingState, sample cgroupMkdirSample) []engineEffect {
	if parentJobID, ok := state.jobForCgroup(sample.ParentCgroupID); ok {
		if !state.bind(parentJobID, sample.CgroupID) {
			return nil
		}
		return nil
	}

	// A staging match means the kernel accepted this untracked-parent mkdir.
	// Mirror ownership; the kernel has already consumed staging_map.
	if sample.StagingMatched {
		basename := filepath.Base(sample.CgroupPath)
		if _, ok := state.promoteStagedCgroup(basename, sample.CgroupID); ok {
			return nil
		}
	}

	return nil
}

// handleCgroupAttachSample mirrors attach-driven cgroup ownership changes.
// cgroup_attach is internal tracking state, not a user-facing event.
func handleCgroupAttachSample(state *jobTrackingState, sample cgroupAttachSample) []engineEffect {
	ownership := state.lookupCgroupAttachOwnership(sample.SourceCgroupID, sample.DestinationCgroupID)
	if !ownership.SourceFound {
		return nil
	}

	sourceJobID := ownership.SourceJobID

	if ownership.DestinationFound {
		// Existing bindings win. Same-Job attach is already mirrored;
		// cross-Job attach must not reassign destination ownership.
		if ownership.DestinationJobID != sourceJobID {
			if state.logger != nil {
				state.logger.Warn("bpf_cgroup_attach_owner_conflict",
					"source_job_id", sourceJobID,
					"destination_job_id", ownership.DestinationJobID,
					"source_cgroup_id", sample.SourceCgroupID,
					"destination_cgroup_id", sample.DestinationCgroupID,
					"tgid", sample.Tgid,
				)
			}
		}
		return nil
	}

	// The kernel hook already added destination_cgroup_id to tracked_cgroups
	// before emitting this sample; mirror that ownership in userspace.
	state.bind(sourceJobID, sample.DestinationCgroupID)
	return nil
}

func handleCgroupRmdirSample(state *jobTrackingState, sample cgroupRmdirSample) []engineEffect {
	detached := state.markTrackedCgroupRemoved(sample.CgroupID, time.Now().UTC())
	if !detached.Found {
		return nil
	}

	if detached.JobDrained {
		return []engineEffect{notifyJobEnded{JobID: detached.JobID, Reason: EndCgroupRmdir}}
	}

	return nil
}

func handleCgroupLivenessReconciliation(state *jobTrackingState, command commandReconcileCgroupLiveness) []engineEffect {
	removed := state.reconcileCgroupLiveness(command.LiveCgroupIDs, command.ScanStartedAt, command.CheckedAt)
	if len(removed) == 0 {
		return nil
	}

	var effects []engineEffect
	drainedJobs := 0
	for _, result := range removed {
		if result.JobDrained {
			drainedJobs++
			effects = append(effects, notifyJobEnded{JobID: result.JobID, Reason: EndCgroupRmdir})
		}
	}
	if state.logger != nil {
		state.logger.Info("cgroup_liveness_reconciled",
			"removed_count", len(removed),
			"drained_job_count", drainedJobs,
			"live_cgroup_count", len(command.LiveCgroupIDs),
			"stat_error_count", command.StatErrorCount,
		)
	}
	return effects
}
