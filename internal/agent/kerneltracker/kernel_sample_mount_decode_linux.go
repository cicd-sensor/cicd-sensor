//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func decodeMountSample(raw []byte) (mountSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramMountSample{}) {
		return mountSample{}, fmt.Errorf("unexpected mount sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramMountSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return mountSample{}, fmt.Errorf("read mount sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindMount {
		return mountSample{}, fmt.Errorf("unexpected mount sample kind %d", sample.Kind)
	}
	return mountSample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:        sample.CgroupId,
		TsNs:            sample.TsNs,
		SourcePath:      pathFromBuffer(sample.SourcePath[:], sample.SourceOffset),
		TargetPath:      pathFromBuffer(sample.TargetPath[:], sample.TargetOffset),
		SourceTruncated: sample.SourceTruncated != 0,
		TargetTruncated: sample.TargetTruncated != 0,
	}, nil
}
