package kerneltracker

import (
	"log/slog"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

// jobTrackingState is the loop-local Job mirror owned by KernelTracker.Run.
type jobTrackingState struct {
	logger                *slog.Logger
	jobs                  map[jobcontext.JobIdentity]struct{}
	jobEventChannels      map[jobcontext.JobIdentity]chan jobevent.EventRecord
	jobEventDeliveryStats map[jobcontext.JobIdentity]map[jobevent.Type]*eventDeliveryStats
	fileOpenDedupByJob    map[jobcontext.JobIdentity]*fileOpenDedupState
	jobByCgroup           map[uint64]jobcontext.JobIdentity
	cgroupsByJob          map[jobcontext.JobIdentity]map[uint64]struct{}
	stagingByBasename     map[string]jobcontext.JobIdentity
	stagingByJob          map[jobcontext.JobIdentity]map[string]struct{}
	processesByJob        map[jobcontext.JobIdentity]*jobProcessState
}

func newJobTrackingState() *jobTrackingState {
	return &jobTrackingState{
		jobs:                  make(map[jobcontext.JobIdentity]struct{}),
		jobEventChannels:      make(map[jobcontext.JobIdentity]chan jobevent.EventRecord),
		jobEventDeliveryStats: make(map[jobcontext.JobIdentity]map[jobevent.Type]*eventDeliveryStats),
		fileOpenDedupByJob:    make(map[jobcontext.JobIdentity]*fileOpenDedupState),
		jobByCgroup:           make(map[uint64]jobcontext.JobIdentity),
		cgroupsByJob:          make(map[jobcontext.JobIdentity]map[uint64]struct{}),
		stagingByBasename:     make(map[string]jobcontext.JobIdentity),
		stagingByJob:          make(map[jobcontext.JobIdentity]map[string]struct{}),
		processesByJob:        make(map[jobcontext.JobIdentity]*jobProcessState),
	}
}

func (s *jobTrackingState) registerJob(jobID jobcontext.JobIdentity, eventRecordBufferSize int) chan jobevent.EventRecord {
	s.jobs[jobID] = struct{}{}

	if s.processesByJob[jobID] == nil {
		s.processesByJob[jobID] = newJobProcessState()
	}
	if s.fileOpenDedupByJob[jobID] == nil {
		s.fileOpenDedupByJob[jobID] = newFileOpenDedupState(defaultFileOpenDedupKeyLimit)
	}

	channel := s.jobEventChannels[jobID]
	if channel == nil {
		channel = make(chan jobevent.EventRecord, eventRecordBufferSize)
		s.jobEventChannels[jobID] = channel
	}

	return channel
}

type eventDeliveryStats struct {
	Attempted            uint64
	Delivered            uint64
	Dropped              uint64
	SuppressedDuplicates uint64
	MaxQueueDepth        int
}

func (s *eventDeliveryStats) observeQueueDepth(depth int) {
	if depth > s.MaxQueueDepth {
		s.MaxQueueDepth = depth
	}
}

func (s *jobTrackingState) deliveryStatsFor(jobID jobcontext.JobIdentity, eventType jobevent.Type) *eventDeliveryStats {
	byEventType := s.jobEventDeliveryStats[jobID]
	if byEventType == nil {
		byEventType = make(map[jobevent.Type]*eventDeliveryStats)
		s.jobEventDeliveryStats[jobID] = byEventType
	}
	stats := byEventType[eventType]
	if stats == nil {
		stats = &eventDeliveryStats{}
		byEventType[eventType] = stats
	}
	return stats
}

func (s *jobTrackingState) removeJob(jobID jobcontext.JobIdentity) chan jobevent.EventRecord {
	channel := s.jobEventChannels[jobID]
	delete(s.jobEventChannels, jobID)
	delete(s.jobEventDeliveryStats, jobID)
	delete(s.fileOpenDedupByJob, jobID)
	s.removeCgroupAndStaging(jobID)
	delete(s.jobs, jobID)
	delete(s.processesByJob, jobID)

	return channel
}
