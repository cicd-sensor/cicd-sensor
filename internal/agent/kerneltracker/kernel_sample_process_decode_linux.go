//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func decodeForkSample(raw []byte) (forkSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramForkSample{}) {
		return forkSample{}, fmt.Errorf("unexpected fork sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramForkSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return forkSample{}, fmt.Errorf("read fork sample: %w", err)
	}

	if sample.Kind != kernelio.SampleKindFork {
		return forkSample{}, fmt.Errorf("unexpected fork sample kind %d", sample.Kind)
	}

	return forkSample{
		Child: processIdentity{
			PID:           sample.ChildTgid,
			StartBoottime: sample.ChildStartBoottime,
		},
		Parent: processIdentity{
			PID:           sample.ParentTgid,
			StartBoottime: sample.ParentStartBoottime,
		},
		ChildCgroupID: sample.CgroupId,
		TsNs:          sample.TsNs,
	}, nil
}

func decodeExecSample(raw []byte) (execSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramExecSample{}) {
		return execSample{}, fmt.Errorf("unexpected exec sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramExecSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return execSample{}, fmt.Errorf("read exec sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindExec {
		return execSample{}, fmt.Errorf("unexpected exec sample kind %d", sample.Kind)
	}
	argvBlob, err := cBytes(sample.ArgvBlob[:], sample.ArgvBlobLen)
	if err != nil {
		return execSample{}, fmt.Errorf("read exec argv blob: %w", err)
	}

	return execSample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:      sample.CgroupId,
		TsNs:          sample.TsNs,
		ExecPath:      cString(sample.ExecPath[:]),
		Argc:          sample.Argc,
		ArgvBlob:      argvBlob,
		ArgvTruncated: sample.ArgvTruncated != 0,
		ArgvFaulted:   sample.ArgvFaulted != 0,
		IsMemfd:       sample.IsMemfd != 0,
	}, nil
}
