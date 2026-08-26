//go:build linux

package kernelio

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
)

// handleHTTPUprobeMappingSample keeps KernelIO control samples out of the
// KernelTracker security-event path.
func (kernelIO *LinuxKernelIO) handleHTTPUprobeMappingSample(raw []byte) (bool, error) {
	if len(raw) < 4 || binary.LittleEndian.Uint32(raw[:4]) != SampleKindHTTPUprobeMapping {
		return false, nil
	}
	if kernelIO.httpUprobeDiscovery == nil {
		return true, nil
	}

	mapping, err := decodeHTTPUprobeMappingSample(raw)
	if err != nil {
		return true, err
	}
	kernelIO.httpUprobeDiscovery.queueMapping(mapping)
	return true, nil
}

func decodeHTTPUprobeMappingSample(raw []byte) (httpUprobeMapping, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramHttpUprobeMappingSample{}) {
		return httpUprobeMapping{}, fmt.Errorf("unexpected HTTP uprobe mapping sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramHttpUprobeMappingSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return httpUprobeMapping{}, fmt.Errorf("decode HTTP uprobe mapping sample: %w", err)
	}
	if sample.Kind != SampleKindHTTPUprobeMapping {
		return httpUprobeMapping{}, fmt.Errorf("unexpected HTTP uprobe mapping sample kind %d", sample.Kind)
	}

	return httpUprobeMapping{
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
