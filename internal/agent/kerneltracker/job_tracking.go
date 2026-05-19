package kerneltracker

import (
	"fmt"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func handleStageCgroupBasename(state *jobTrackingState, command commandStageCgroupBasename) []engineEffect {
	if command.Basename == "" || strings.Contains(command.Basename, "/") || len(command.Basename) > kernelio.StagingKeyLen {
		return []engineEffect{replyStageCgroupBasename{
			Reply: command.Reply,
			Err:   fmt.Errorf("invalid staging basename %q (len=%d)", command.Basename, len(command.Basename)),
		}}
	}

	owner, exists := state.stagingByBasename[command.Basename]
	if exists && owner != command.JobID {
		return []engineEffect{replyStageCgroupBasename{
			Reply: command.Reply,
			Err:   fmt.Errorf("staging basename %q already belongs to another job", command.Basename),
		}}
	}

	return []engineEffect{stageCgroupBasename{
		Basename: command.Basename,
		JobID:    command.JobID,
		Reply:    command.Reply,
	}}
}

// handleRegisterJob registers (or refreshes) Job state and allocates the
// per-Job event channel. cgroup binding is a separate command handled by
// handleBindCgroup; RegisterJob does not touch tracked_cgroups.
func handleRegisterJob(state *jobTrackingState, command commandRegisterJob) []engineEffect {
	if _, registered := state.jobs[command.JobID]; registered {
		channel := state.jobEventChannels[command.JobID]
		return []engineEffect{
			replyRegisterJob{
				Reply:   command.Reply,
				EventCh: channel,
			},
		}
	}

	channel := state.registerJob(command.JobID, defaultEventRecordBufferSize)
	return []engineEffect{replyRegisterJob{
		Reply:   command.Reply,
		EventCh: channel,
	}}
}

// handleBindCgroup binds cgroup → jobID in tracked_cgroups. The Job must
// already be registered via handleRegisterJob; otherwise the bind errors out
// so the caller can decide whether to retry-after-register or surface the
// failure. A cgroup already bound to another Job is also rejected — bind
// is non-overwriting to prevent silent ownership theft.
func handleBindCgroup(state *jobTrackingState, command commandBindCgroup) []engineEffect {
	var err error
	if _, registered := state.jobs[command.JobID]; !registered {
		err = fmt.Errorf("bind cgroup %d: job not registered", command.CgroupID)
	} else if owner, ok := state.jobForCgroup(command.CgroupID); ok && owner != command.JobID {
		err = fmt.Errorf("cgroup %d already bound to another job", command.CgroupID)
	}
	if err != nil {
		return []engineEffect{
			replyBindCgroup{
				Reply: command.Reply,
				Err:   err,
			},
		}
	}
	return []engineEffect{bindTrackedCgroup{
		JobID:    command.JobID,
		CgroupID: command.CgroupID,
		Reply:    command.Reply,
	}}
}

func handleRemoveJob(state *jobTrackingState, command commandRemoveJob) []engineEffect {
	if _, registered := state.jobs[command.JobID]; !registered {
		return []engineEffect{replyRemoveJob{Reply: command.Reply}}
	}

	return []engineEffect{removeJobFromKernel{
		JobID:   command.JobID,
		Cgroups: state.cgroupsForJob(command.JobID),
		Staging: state.stagingForJob(command.JobID),
		Reply:   command.Reply,
	}}
}
