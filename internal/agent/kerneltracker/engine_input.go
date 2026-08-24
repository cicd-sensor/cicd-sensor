package kerneltracker

import (
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

// engineInput is one item serialized through the job tracking loop.
type engineInput interface {
	sealedEngineInput()
}

// decodedKernelSample is a kernel-derived job tracking input.
type decodedKernelSample interface {
	engineInput
	sealedDecodedKernelSample()
}

type commandRegisterJob struct {
	JobID jobcontext.JobIdentity
	Reply chan<- registerJobReply
}

func (commandRegisterJob) sealedEngineInput() {}

type registerJobReply struct {
	EventCh <-chan jobevent.EventRecord
	Err     error
}

type commandBindCgroup struct {
	JobID    jobcontext.JobIdentity
	CgroupID uint64
	Reply    chan<- error
}

func (commandBindCgroup) sealedEngineInput() {}

type commandRemoveJob struct {
	JobID jobcontext.JobIdentity
	Reply chan<- error
}

func (commandRemoveJob) sealedEngineInput() {}

type commandStageCgroupBasename struct {
	Basename string
	JobID    jobcontext.JobIdentity
	Reply    chan<- error
}

func (commandStageCgroupBasename) sealedEngineInput() {}

type commandFindJobForCgroup struct {
	CgroupID uint64
	Reply    chan<- JobForCgroupResult
}

func (commandFindJobForCgroup) sealedEngineInput() {}

type commandPurgeExpiredTrackingState struct{}

func (commandPurgeExpiredTrackingState) sealedEngineInput() {}

type commandReconcileCgroupLiveness struct {
	ScanStartedAt  time.Time
	CheckedAt      time.Time
	LiveCgroupIDs  map[uint64]struct{}
	StatErrorCount int
}

func (commandReconcileCgroupLiveness) sealedEngineInput() {}
