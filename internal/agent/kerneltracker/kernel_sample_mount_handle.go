package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/jobevent"

type mountSample struct {
	Identity        processIdentity
	CgroupID        uint64
	TsNs            uint64
	SourcePath      string
	TargetPath      string
	SourceTruncated bool
	TargetTruncated bool
}

func (mountSample) sealedEngineInput()         {}
func (mountSample) sealedDecodedKernelSample() {}

func handleMountSample(state *jobTrackingState, sample mountSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	record := jobevent.EventRecord{
		EventType: jobevent.Mount,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"source_path": sample.SourcePath,
			"target_path": sample.TargetPath,
		},
		Tags: map[string]string{},
	}
	switch {
	case sample.SourceTruncated && sample.TargetTruncated:
		record.Tags["truncated"] = "source_path,target_path"
	case sample.SourceTruncated:
		record.Tags["truncated"] = "source_path"
	case sample.TargetTruncated:
		record.Tags["truncated"] = "target_path"
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}
