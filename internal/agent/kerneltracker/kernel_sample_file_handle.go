package kerneltracker

import (
	"path"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

type fileOpenSample struct {
	Identity      processIdentity
	CgroupID      uint64
	TsNs          uint64
	Path          string
	Flags         uint32
	IsWrite       bool
	IsRead        bool
	PathTruncated bool
}

func (fileOpenSample) sealedEngineInput()         {}
func (fileOpenSample) sealedDecodedKernelSample() {}

type fileRemoveSample struct {
	Identity      processIdentity
	CgroupID      uint64
	TsNs          uint64
	Path          string
	IsFolder      bool
	PathTruncated bool
}

func (fileRemoveSample) sealedEngineInput()         {}
func (fileRemoveSample) sealedDecodedKernelSample() {}

type fileMoveSample struct {
	Identity      processIdentity
	CgroupID      uint64
	TsNs          uint64
	FromPath      string
	ToPath        string
	FromTruncated bool
	ToTruncated   bool
}

func (fileMoveSample) sealedEngineInput()         {}
func (fileMoveSample) sealedDecodedKernelSample() {}

type fileLinkSample struct {
	Identity          processIdentity
	CgroupID          uint64
	TsNs              uint64
	CreatedPath       string
	ExistingPath      string
	IsHardlink        bool
	IsSymlink         bool
	CreatedTruncated  bool
	ExistingTruncated bool
}

func (fileLinkSample) sealedEngineInput()         {}
func (fileLinkSample) sealedDecodedKernelSample() {}

func handleFileOpenSample(state *jobTrackingState, sample fileOpenSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	record := jobevent.EventRecord{
		EventType: jobevent.FileOpen,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"path":     sample.Path,
			"is_write": sample.IsWrite,
			"is_read":  sample.IsRead,
			"flags":    int(sample.Flags),
		},
		Tags: map[string]string{},
	}
	if sample.PathTruncated {
		record.Tags["truncated"] = "path"
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}

func handleFileRemoveSample(state *jobTrackingState, sample fileRemoveSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	record := jobevent.EventRecord{
		EventType: jobevent.FileRemove,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"path":      sample.Path,
			"is_folder": sample.IsFolder,
		},
		Tags: map[string]string{},
	}
	if sample.PathTruncated {
		record.Tags["truncated"] = "path"
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}

func handleFileMoveSample(state *jobTrackingState, sample fileMoveSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	record := jobevent.EventRecord{
		EventType: jobevent.FileMove,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"from_path": sample.FromPath,
			"to_path":   sample.ToPath,
		},
		Tags: map[string]string{},
	}
	if sample.FromTruncated || sample.ToTruncated {
		record.Tags["truncated"] = "path"
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}

func handleFileLinkSample(state *jobTrackingState, sample fileLinkSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	existing := sample.ExistingPath
	if sample.IsSymlink && existing != "" && !strings.HasPrefix(existing, "/") {
		existing = path.Clean(path.Join(path.Dir(sample.CreatedPath), existing))
	}

	record := jobevent.EventRecord{
		EventType: jobevent.FileLink,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"created_path":  sample.CreatedPath,
			"existing_path": existing,
			"is_hardlink":   sample.IsHardlink,
			"is_symlink":    sample.IsSymlink,
		},
		Tags: map[string]string{},
	}
	if sample.CreatedTruncated || sample.ExistingTruncated {
		record.Tags["truncated"] = "path"
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}
