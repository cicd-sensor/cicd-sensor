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

func handleCgroupFilesystemSnapshot(state *jobTrackingState, snapshot cgroupFilesystemSnapshot) []engineEffect {
	// Apply the filesystem snapshot to loop-owned cgroup state first. This
	// excludes cgroups tracked after ScanStartedAt and returns only paths that
	// were both tracked and present in this snapshot.
	reconciliation := state.reconcileCgroupFilesystem(snapshot)

	// After cgroup state is reconciled, queue its active paths for the
	// single-owner HTTP uprobe worker. It expands cgroup.procs and reconciles
	// mapped files asynchronously.
	effects := []engineEffect{queueHTTPUprobeTargetReconciliation{
		ActiveCgroupPaths: reconciliation.ActiveCgroupPaths,
	}}

	drainedJobs := 0
	for _, result := range reconciliation.Removed {
		if result.JobDrained {
			drainedJobs++
			effects = append(effects, notifyJobEnded{JobID: result.JobID, Reason: EndCgroupRmdir})
		}
	}
	if len(reconciliation.Removed) > 0 && state.logger != nil {
		state.logger.Info("cgroup_liveness_reconciled",
			"removed_count", len(reconciliation.Removed),
			"drained_job_count", drainedJobs,
			"live_cgroup_count", len(snapshot.CgroupPathsByID),
			"stat_error_count", snapshot.StatErrorCount,
		)
	}
	return effects
}
