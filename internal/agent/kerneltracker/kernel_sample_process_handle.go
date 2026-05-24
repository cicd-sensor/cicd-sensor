package kerneltracker

import (
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

type forkSample struct {
	Child         processIdentity
	Parent        processIdentity
	ChildCgroupID uint64
	TsNs          uint64
}

func (forkSample) sealedEngineInput()         {}
func (forkSample) sealedDecodedKernelSample() {}

type execSample struct {
	Identity      processIdentity
	CgroupID      uint64
	TsNs          uint64
	ExecPath      string
	Argc          uint32
	ArgvBlob      []byte
	ArgvTruncated bool
	ArgvFaulted   bool
	IsMemfd       bool
}

func (execSample) sealedEngineInput()         {}
func (execSample) sealedDecodedKernelSample() {}

type exitSample struct {
	Identity processIdentity
	CgroupID uint64
	TsNs     uint64
}

func (exitSample) sealedEngineInput()         {}
func (exitSample) sealedDecodedKernelSample() {}

func handleForkSample(state *jobTrackingState, sample forkSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.ChildCgroupID)
	if !ok {
		return nil
	}

	if !state.recordFork(jobID, sample.Child, sample.Parent) {
		return nil
	}
	return nil
}

func handleExecSample(state *jobTrackingState, sample execSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	process, ok := state.recordExec(jobID, sample.Identity, sample.ExecPath, sample.ArgvBlob, sample.Argc)
	if !ok {
		return nil
	}

	// process_exec sample payload carries sample-kind-specific signals only.
	// exec_path / argv are not duplicated here; rules read them via the
	// top-level Process field (process.exec_path / process.argv).
	record := jobevent.EventRecord{
		EventType: jobevent.ProcessExec,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   process,
		Payload: map[string]any{
			"is_memfd": sample.IsMemfd,
		},
		Tags: map[string]string{},
	}
	if sample.ArgvTruncated {
		record.Tags["truncated"] = "argv"
	}
	if sample.ArgvFaulted {
		record.Tags["faulted"] = "argv"
	}

	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}

func handleExitSample(state *jobTrackingState, sample exitSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	state.recordExit(jobID, sample.Identity, time.Now().UTC())
	return nil
}

func handlePurgeTick(state *jobTrackingState) []engineEffect {
	state.purgeExitedProcesses(time.Now().UTC())
	return nil
}
