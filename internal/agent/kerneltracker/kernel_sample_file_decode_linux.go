//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func decodeFileRemoveSample(raw []byte) (fileRemoveSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramFileRemoveSample{}) {
		return fileRemoveSample{}, fmt.Errorf("unexpected file remove sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramFileRemoveSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return fileRemoveSample{}, fmt.Errorf("read file remove sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindFileRemove {
		return fileRemoveSample{}, fmt.Errorf("unexpected file remove sample kind %d", sample.Kind)
	}

	return fileRemoveSample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:      sample.CgroupId,
		TsNs:          sample.TsNs,
		Path:          pathFromBuffer(sample.Path[:], sample.PathOffset),
		IsFolder:      sample.IsFolder != 0,
		PathTruncated: sample.PathTruncated != 0,
	}, nil
}

func decodeFileMoveSample(raw []byte) (fileMoveSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramFileMoveSample{}) {
		return fileMoveSample{}, fmt.Errorf("unexpected file move sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramFileMoveSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return fileMoveSample{}, fmt.Errorf("read file move sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindFileMove {
		return fileMoveSample{}, fmt.Errorf("unexpected file move sample kind %d", sample.Kind)
	}

	return fileMoveSample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:      sample.CgroupId,
		TsNs:          sample.TsNs,
		FromPath:      pathFromBuffer(sample.FromPath[:], sample.FromOffset),
		ToPath:        pathFromBuffer(sample.ToPath[:], sample.ToOffset),
		FromTruncated: sample.FromTruncated != 0,
		ToTruncated:   sample.ToTruncated != 0,
	}, nil
}

func decodeFileLinkSample(raw []byte) (fileLinkSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramFileLinkSample{}) {
		return fileLinkSample{}, fmt.Errorf("unexpected file link sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramFileLinkSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return fileLinkSample{}, fmt.Errorf("read file link sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindFileLink {
		return fileLinkSample{}, fmt.Errorf("unexpected file link sample kind %d", sample.Kind)
	}

	return fileLinkSample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:          sample.CgroupId,
		TsNs:              sample.TsNs,
		CreatedPath:       pathFromBuffer(sample.CreatedPath[:], sample.CreatedOffset),
		ExistingPath:      pathFromBuffer(sample.ExistingPath[:], sample.ExistingOffset),
		IsHardlink:        sample.IsHardlink != 0,
		IsSymlink:         sample.IsSymlink != 0,
		CreatedTruncated:  sample.CreatedTruncated != 0,
		ExistingTruncated: sample.ExistingTruncated != 0,
	}, nil
}

func decodeFileOpenSample(raw []byte) (fileOpenSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramFileOpenSample{}) {
		return fileOpenSample{}, fmt.Errorf("unexpected file open sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramFileOpenSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return fileOpenSample{}, fmt.Errorf("read file open sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindFileOpen {
		return fileOpenSample{}, fmt.Errorf("unexpected file open sample kind %d", sample.Kind)
	}

	return fileOpenSample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:          sample.CgroupId,
		TsNs:              sample.TsNs,
		Path:              cString(sample.Path[:]),
		ResolvedPath:      pathFromBuffer(sample.ResolvedPath[:], sample.ResolvedOffset),
		Flags:             sample.Flags,
		IsWrite:           sample.IsWrite != 0,
		IsRead:            sample.IsRead != 0,
		PathTruncated:     sample.PathTruncated != 0,
		ResolvedTruncated: sample.ResolvedTruncated != 0,
	}, nil
}
