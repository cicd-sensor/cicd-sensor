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

const (
	fileOpenPayloadPath    = "path"
	fileOpenPayloadIsRead  = "is_read"
	fileOpenPayloadIsWrite = "is_write"
	fileOpenPayloadFlags   = "flags"
)

// fileOpenRecordPayload is what file_open dedup reads from EventRecord.Payload.
// fileOpenDedupKey embeds this type so rule-visible payload changes also change
// duplicate-suppression identity.
type fileOpenRecordPayload struct {
	Path    string
	IsRead  bool
	IsWrite bool
	Flags   int
}

func fileOpenPayloadFromRecord(record jobevent.EventRecord) (fileOpenRecordPayload, bool) {
	if record.EventType != jobevent.FileOpen {
		return fileOpenRecordPayload{}, false
	}
	pathValue, ok := record.Payload[fileOpenPayloadPath].(string)
	if !ok || pathValue == "" {
		return fileOpenRecordPayload{}, false
	}
	isRead, ok := record.Payload[fileOpenPayloadIsRead].(bool)
	if !ok {
		return fileOpenRecordPayload{}, false
	}
	isWrite, ok := record.Payload[fileOpenPayloadIsWrite].(bool)
	if !ok {
		return fileOpenRecordPayload{}, false
	}
	flags, ok := record.Payload[fileOpenPayloadFlags].(int)
	if !ok {
		return fileOpenRecordPayload{}, false
	}
	return fileOpenRecordPayload{
		Path:    pathValue,
		IsRead:  isRead,
		IsWrite: isWrite,
		Flags:   flags,
	}, true
}

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
			fileOpenPayloadPath:    sample.Path,
			fileOpenPayloadIsRead:  sample.IsRead,
			fileOpenPayloadIsWrite: sample.IsWrite,
			fileOpenPayloadFlags:   int(sample.Flags),
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
