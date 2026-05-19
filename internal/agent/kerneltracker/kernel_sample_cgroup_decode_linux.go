//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func decodeCgroupMkdirSample(raw []byte) (cgroupMkdirSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramCgroupMkdirSample{}) {
		return cgroupMkdirSample{}, fmt.Errorf("unexpected cgroup mkdir sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramCgroupMkdirSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return cgroupMkdirSample{}, fmt.Errorf("read cgroup mkdir sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindCgroupMkdir {
		return cgroupMkdirSample{}, fmt.Errorf("unexpected cgroup mkdir sample kind %d", sample.Kind)
	}

	return cgroupMkdirSample{
		CgroupID:       sample.CgroupId,
		ParentCgroupID: sample.ParentCgroupId,
		CgroupPath:     cString(sample.Path[:]),
		TsNs:           sample.TsNs,
		StagingMatched: sample.StagingMatched != 0,
	}, nil
}

func decodeCgroupAttachSample(raw []byte) (cgroupAttachSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramCgroupAttachSample{}) {
		return cgroupAttachSample{}, fmt.Errorf("unexpected cgroup attach sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramCgroupAttachSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return cgroupAttachSample{}, fmt.Errorf("read cgroup attach sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindCgroupAttach {
		return cgroupAttachSample{}, fmt.Errorf("unexpected cgroup attach sample kind %d", sample.Kind)
	}

	return cgroupAttachSample{
		Tgid:                sample.Tgid,
		SourceCgroupID:      sample.SourceCgroupId,
		DestinationCgroupID: sample.DestinationCgroupId,
		TsNs:                sample.TsNs,
	}, nil
}

func decodeCgroupRmdirSample(raw []byte) (cgroupRmdirSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramCgroupRmdirSample{}) {
		return cgroupRmdirSample{}, fmt.Errorf("unexpected cgroup rmdir sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramCgroupRmdirSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return cgroupRmdirSample{}, fmt.Errorf("read cgroup rmdir sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindCgroupRmdir {
		return cgroupRmdirSample{}, fmt.Errorf("unexpected cgroup rmdir sample kind %d", sample.Kind)
	}

	return cgroupRmdirSample{
		CgroupID: sample.CgroupId,
		TsNs:     sample.TsNs,
	}, nil
}
