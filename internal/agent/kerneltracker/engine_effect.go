package kerneltracker

import (
	"context"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

// engineEffect is side-effect work produced after jobTrackingState changes.
type engineEffect interface {
	sealedEngineEffect()
}

type emitEventRecord struct {
	JobID  jobcontext.JobIdentity
	Record jobevent.EventRecord
}

func (emitEventRecord) sealedEngineEffect() {}

type notifyJobEnded struct {
	JobID  jobcontext.JobIdentity
	Reason EndReason
}

func (notifyJobEnded) sealedEngineEffect() {}

type replyRegisterJob struct {
	Reply   chan<- registerJobReply
	EventCh <-chan jobevent.EventRecord
	Err     error
}

func (replyRegisterJob) sealedEngineEffect() {}

type replyBindCgroup struct {
	Reply chan<- error
	Err   error
}

func (replyBindCgroup) sealedEngineEffect() {}

type replyStageCgroupBasename struct {
	Reply chan<- error
	Err   error
}

func (replyStageCgroupBasename) sealedEngineEffect() {}

type replyRemoveJob struct {
	Reply chan<- error
	Err   error
}

func (replyRemoveJob) sealedEngineEffect() {}

type replyJobForCgroup struct {
	Reply  chan<- JobForCgroupResult
	Result JobForCgroupResult
}

func (replyJobForCgroup) sealedEngineEffect() {}

type closeEventChannel struct {
	Channel chan jobevent.EventRecord
}

func (closeEventChannel) sealedEngineEffect() {}

type bindTrackedCgroup struct {
	JobID    jobcontext.JobIdentity
	CgroupID uint64
	Reply    chan<- error
}

func (bindTrackedCgroup) sealedEngineEffect() {}

type stageCgroupBasename struct {
	Basename string
	JobID    jobcontext.JobIdentity
	Reply    chan<- error
}

func (stageCgroupBasename) sealedEngineEffect() {}

type removeJobFromKernel struct {
	JobID   jobcontext.JobIdentity
	Cgroups []uint64
	Staging []string
	Reply   chan<- error
}

func (removeJobFromKernel) sealedEngineEffect() {}

func (engine *KernelTracker) runEngineEffects(ctx context.Context, effects []engineEffect) {
	for _, effect := range effects {
		switch value := effect.(type) {
		case emitEventRecord:
			channel, ok := engine.jobTracking.jobEventChannels[value.JobID]
			if !ok {
				continue
			}

			// Keep delivery pressure stats separately from suppression so job
			// removal can report what reached, skipped, or overflowed the queue.
			stats := engine.jobTracking.deliveryStatsFor(value.JobID, value.Record.EventType)
			stats.Attempted++
			stats.observeQueueDepth(len(channel))

			var fileOpenDedup *fileOpenDedupState
			var fileOpenKey fileOpenDedupKey
			if value.Record.EventType == jobevent.FileOpen {
				// Collapse repeated file_open records before they consume the
				// per-Job EventRecord channel. Other event types are never
				// deduplicated here.
				dedupKey, canDedupFileOpen := fileOpenDedupKeyForRecord(value.Record)
				if canDedupFileOpen {
					dedupState := engine.jobTracking.fileOpenDedupByJob[value.JobID]
					if dedupState.contains(dedupKey) {
						stats.SuppressedDuplicates++
						continue
					}
					fileOpenDedup = dedupState
					fileOpenKey = dedupKey
				}
			}

			select {
			case channel <- value.Record:
				stats.Delivered++
				// Remember only delivered records, so every suppressible key has
				// one visible EventRecord for rule evaluation.
				if fileOpenDedup != nil {
					fileOpenDedup.remember(fileOpenKey)
				}
			default:
				stats.Dropped++
			}
		case notifyJobEnded:
			if engine.jobEndNotifier != nil {
				engine.jobEndNotifier.OnJobEnded(value.JobID, value.Reason)
			}
		case bindTrackedCgroup:
			err := engine.kernelIO.PutCgroupIDInTrackedCgroupsMap(ctx, value.CgroupID)
			if err == nil && !engine.jobTracking.bind(value.JobID, value.CgroupID) {
				err = fmt.Errorf("cgroup %d already bound to another job", value.CgroupID)
			}
			value.Reply <- err
		case stageCgroupBasename:
			err := engine.kernelIO.PutCgroupBasenameInStagingMap(ctx, value.Basename)
			if err == nil && !engine.jobTracking.putStaging(value.Basename, value.JobID) {
				err = fmt.Errorf("staging basename %q already belongs to another job", value.Basename)
			}
			value.Reply <- err
		case removeJobFromKernel:
			err := engine.deleteJobKernelMapEntries(ctx, value.Cgroups, value.Staging)
			if err == nil {
				engine.logEventDeliverySummary(ctx, value.JobID)
				channel := engine.jobTracking.removeJob(value.JobID)
				if channel != nil {
					close(channel)
				}
			}
			if value.Reply != nil {
				value.Reply <- err
			}
		case replyRegisterJob:
			value.Reply <- registerJobReply{EventCh: value.EventCh, Err: value.Err}
		case replyBindCgroup:
			value.Reply <- value.Err
		case replyStageCgroupBasename:
			value.Reply <- value.Err
		case replyRemoveJob:
			if value.Reply != nil {
				value.Reply <- value.Err
			}
		case replyJobForCgroup:
			value.Reply <- value.Result
		case closeEventChannel:
			if value.Channel != nil {
				close(value.Channel)
			}
		}
	}
}

func (engine *KernelTracker) logEventDeliverySummary(ctx context.Context, jobID jobcontext.JobIdentity) {
	for eventType, stats := range engine.jobTracking.jobEventDeliveryStats[jobID] {
		if stats.Dropped == 0 && stats.SuppressedDuplicates == 0 {
			continue
		}
		engine.logger.InfoContext(ctx, "kernel_event_delivery_summary",
			"job_id", jobID,
			"event_type", eventType,
			"attempted", stats.Attempted,
			"delivered", stats.Delivered,
			"dropped", stats.Dropped,
			"suppressed_duplicates", stats.SuppressedDuplicates,
			"max_queue_depth", stats.MaxQueueDepth,
		)
	}
}

func (engine *KernelTracker) deleteJobKernelMapEntries(ctx context.Context, cgroups []uint64, staging []string) error {
	if err := engine.kernelIO.DeleteCgroupIDsFromTrackedCgroupsMap(ctx, cgroups); err != nil {
		engine.logger.WarnContext(ctx, "bpf_tracked_cgroups_delete_failed",
			"error", err,
			"count", len(cgroups),
		)
		return err
	}
	if err := engine.kernelIO.DeleteCgroupBasenamesFromStagingMap(ctx, staging); err != nil {
		engine.logger.WarnContext(ctx, "bpf_staging_entries_delete_failed",
			"error", err,
			"count", len(staging),
		)
		return err
	}
	return nil
}
