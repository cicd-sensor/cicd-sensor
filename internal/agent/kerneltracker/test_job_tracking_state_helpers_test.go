package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/jobcontext"

func newJob(runID string) jobcontext.JobIdentity {
	return jobcontext.GitHubJobIdentity("github.com", "owner/repo", runID, "job", "1", "tracking-id")
}

func testHasTrackedCgroups(state *jobTrackingState, jobID jobcontext.JobIdentity) bool {
	_, ok := state.cgroupsByJob[jobID]
	return ok
}

func newTrackedState(jobID jobcontext.JobIdentity, cgroupIDs ...uint64) *jobTrackingState {
	state := newJobTrackingState()
	state.registerJob(jobID, defaultEventRecordBufferSize)
	for _, cgroupID := range cgroupIDs {
		state.bind(jobID, cgroupID)
	}
	return state
}

func testProcessExists(state *jobTrackingState, jobID jobcontext.JobIdentity, identity processIdentity) bool {
	processes := state.processesByJob[jobID]
	return processes != nil && processes.nodesByIdentity[identity] != nil
}

func testProcessIsExited(state *jobTrackingState, jobID jobcontext.JobIdentity, identity processIdentity) bool {
	processes := state.processesByJob[jobID]
	if processes == nil {
		return false
	}
	node := processes.nodesByIdentity[identity]
	return node != nil && node.State == processStateExited && !node.ExitTimestamp.IsZero()
}

func testProcessNodeCount(state *jobTrackingState, jobID jobcontext.JobIdentity) int {
	processes := state.processesByJob[jobID]
	if processes == nil {
		return 0
	}
	return len(processes.nodesByIdentity)
}

func testExitedProcessCount(state *jobTrackingState, jobID jobcontext.JobIdentity) int {
	processes := state.processesByJob[jobID]
	if processes == nil {
		return 0
	}
	return len(processes.exitedQueue)
}
