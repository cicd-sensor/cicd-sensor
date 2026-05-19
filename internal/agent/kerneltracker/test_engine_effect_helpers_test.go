package kerneltracker

import (
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"testing"
)

func destinationTrackedState(jobID jobcontext.JobIdentity, cgroupIDs ...uint64) *jobTrackingState {
	state := newJobTrackingState()
	state.registerJob(jobID, defaultEventRecordBufferSize)
	for _, cgroupID := range cgroupIDs {
		state.bind(jobID, cgroupID)
	}
	return state
}

func singleEmitEventRecordEffect(effects []engineEffect) (emitEventRecord, bool) {
	var zero emitEventRecord
	if len(effects) != 1 {
		return zero, false
	}

	value, ok := effects[0].(emitEventRecord)
	if !ok {
		return zero, false
	}

	return value, true
}

func assertReplyCount(t *testing.T, effects []engineEffect, want int) {
	t.Helper()

	got := 0
	for _, effect := range effects {
		switch effect.(type) {
		case replyRegisterJob, replyBindCgroup:
			got++
		}
	}
	if got != want {
		t.Fatalf("reply count: got %d, want %d", got, want)
	}
}

func hasNotifyJobEndedEffect(effects []engineEffect) bool {
	for _, effect := range effects {
		if _, ok := effect.(notifyJobEnded); ok {
			return true
		}
	}
	return false
}
