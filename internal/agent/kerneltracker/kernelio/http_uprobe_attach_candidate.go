//go:build linux

package kernelio

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
)

// handleHTTPUprobeAttachCandidate keeps KernelIO control samples out of the
// KernelTracker security-event path.
func (kernelIO *LinuxKernelIO) handleHTTPUprobeAttachCandidate(raw []byte) (bool, error) {
	if len(raw) < 4 || binary.LittleEndian.Uint32(raw[:4]) != SampleKindHTTPUprobeAttachCandidate {
		return false, nil
	}
	if kernelIO.httpUprobeWorker == nil {
		return true, nil
	}

	candidate, err := decodeHTTPUprobeAttachCandidate(raw)
	if err != nil {
		return true, err
	}
	kernelIO.httpUprobeWorker.queueAttachCandidate(candidate)
	return true, nil
}

func decodeHTTPUprobeAttachCandidate(raw []byte) (httpUprobeAttachCandidate, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramHttpUprobeAttachCandidateSample{}) {
		return httpUprobeAttachCandidate{}, fmt.Errorf("unexpected HTTP uprobe attach candidate size %d", len(raw))
	}

	var sample bpfprog.BPFProgramHttpUprobeAttachCandidateSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return httpUprobeAttachCandidate{}, fmt.Errorf("decode HTTP uprobe attach candidate: %w", err)
	}
	if sample.Kind != SampleKindHTTPUprobeAttachCandidate {
		return httpUprobeAttachCandidate{}, fmt.Errorf("unexpected HTTP uprobe attach candidate kind %d", sample.Kind)
	}

	return httpUprobeAttachCandidate{
		tgid:    sample.Tgid,
		vmStart: sample.VmStart,
		vmEnd:   sample.VmEnd,
		file: fileClassificationKey{
			mappedFile: mappedFileIdentity{
				deviceMajor: sample.File.MappedFile.DeviceMajor,
				deviceMinor: sample.File.MappedFile.DeviceMinor,
				inode:       sample.File.MappedFile.Inode,
			},
			ctimeSec:  sample.File.CtimeSec,
			ctimeNsec: sample.File.CtimeNsec,
		},
	}, nil
}
