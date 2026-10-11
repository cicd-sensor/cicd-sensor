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
	if len(raw) >= 4 && binary.LittleEndian.Uint32(raw[:4]) == SampleKindCgroupRmdir {
		kernelIO.QueueHTTPUprobeReconciliation()
	}
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
		tgid:     sample.Tgid,
		cgroupID: sample.CgroupId, rootCgroupID: sample.RootCgroupId,
		vmStart: sample.VmStart,
		vmEnd:   sample.VmEnd,
		file:    fileKeyFromBPF(sample.File),
	}, nil
}

func fileKeyFromBPF(file bpfprog.BPFProgramFileClassificationKey) fileClassificationKey {
	return fileClassificationKey{
		mappedFile: mappedFileIdentity{
			deviceMajor: file.MappedFile.DeviceMajor,
			deviceMinor: file.MappedFile.DeviceMinor,
			inode:       file.MappedFile.Inode,
		},
		ctimeSec:  file.CtimeSec,
		ctimeNsec: file.CtimeNsec,
	}
}
