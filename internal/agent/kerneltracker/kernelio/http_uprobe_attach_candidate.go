//go:build linux

package kernelio

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
)

// handleHTTPUprobeAttachCandidate consumes one record from the dedicated
// attach-control ring buffer without entering the KernelTracker event path.
func (kernelIO *LinuxKernelIO) handleHTTPUprobeAttachCandidate(raw []byte) error {
	if kernelIO.httpUprobeWorker == nil {
		return nil
	}

	candidate, err := decodeHTTPUprobeAttachCandidate(raw)
	if err != nil {
		decodeErr := fmt.Errorf("decode %d-byte attach candidate: %w", len(raw), err)
		kernelIO.failHTTPUprobeDiscovery(decodeErr)
		return decodeErr
	}
	if candidate.stopRequested {
		tracked, err := kernelIO.httpUprobeStopController.track(candidate)
		if err != nil {
			trackErr := fmt.Errorf("track stopped process %d: %w", candidate.process.TGID, err)
			kernelIO.failHTTPUprobeDiscovery(trackErr)
			return trackErr
		}
		candidate.stopRequested = tracked
	} else if candidate.stopStartedNS == 0 {
		kernelIO.httpUprobeWorker.warnThrottled(
			&kernelIO.httpUprobeWorker.stopNotEstablished,
			"http_uprobe_stop_not_established",
			"tgid", candidate.process.TGID,
		)
	}
	// A non-zero stop timestamp with stopped=false belongs to an existing stop
	// lease. Queue it without starting or tracking another stop.
	kernelIO.httpUprobeWorker.queueAttachCandidate(candidate)
	return nil
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
		process: httpUprobeProcessGeneration{
			TGID:          sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		vmStart:       sample.VmStart,
		vmEnd:         sample.VmEnd,
		stopRequested: sample.StopRequested != 0,
		stopStartedNS: sample.StopStartedNs,
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
