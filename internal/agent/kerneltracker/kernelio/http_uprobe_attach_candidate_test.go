//go:build linux

package kernelio

import (
	"bytes"
	"encoding/binary"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
)

func TestDecodeHTTPUprobeAttachCandidate(t *testing.T) {
	want := httpUprobeAttachCandidate{
		process:       httpUprobeProcessGeneration{TGID: 1234, StartBoottime: 5678},
		vmStart:       0x400000,
		vmEnd:         0x401000,
		stopRequested: true,
		stopStartedNS: 9012,
		file: fileClassificationKey{
			mappedFile: mappedFileIdentity{deviceMajor: 8, deviceMinor: 1, inode: 99},
			ctimeSec:   123,
			ctimeNsec:  456,
		},
	}
	raw := encodeHTTPUprobeAttachCandidate(t, want)

	t.Run("valid mapping preserves the BPF ABI", func(t *testing.T) {
		got, err := decodeHTTPUprobeAttachCandidate(raw)
		if err != nil {
			t.Fatalf("decodeHTTPUprobeAttachCandidate: %v", err)
		}
		if got != want {
			t.Fatalf("mapping = %+v, want %+v", got, want)
		}
	})

	t.Run("short sample cannot be partially decoded", func(t *testing.T) {
		if _, err := decodeHTTPUprobeAttachCandidate(raw[:len(raw)-1]); err == nil {
			t.Fatal("decodeHTTPUprobeAttachCandidate succeeded for a short sample")
		}
	})

	t.Run("wrong sample kind cannot enter the private control path", func(t *testing.T) {
		raw := bytes.Clone(raw)
		binary.LittleEndian.PutUint32(raw[:4], 1)
		if _, err := decodeHTTPUprobeAttachCandidate(raw); err == nil {
			t.Fatal("decodeHTTPUprobeAttachCandidate succeeded for the wrong sample kind")
		}
	})
}

func TestFileClassificationKeyBPFMapABI(t *testing.T) {
	got := binary.Size(fileClassificationKey{})
	want := binary.Size(bpfprog.BPFProgramFileClassificationKey{})
	if got != want {
		t.Fatalf("file classification key size = %d, want BPF map key size %d", got, want)
	}
}

func TestHandleHTTPUprobeAttachCandidate(t *testing.T) {
	candidate := httpUprobeAttachCandidate{process: httpUprobeProcessGeneration{TGID: 1234}, vmStart: 0x400000, vmEnd: 0x401000}

	t.Run("attach candidate is queued without entering KernelTracker", func(t *testing.T) {
		worker := &httpUprobeWorker{attachCandidates: make(chan httpUprobeAttachCandidate, 1)}
		kernelIO := &LinuxKernelIO{httpUprobeWorker: worker}
		if err := kernelIO.handleHTTPUprobeAttachCandidate(encodeHTTPUprobeAttachCandidate(t, candidate)); err != nil {
			t.Fatalf("handleHTTPUprobeAttachCandidate: %v", err)
		}
		if got := <-worker.attachCandidates; got != candidate {
			t.Fatalf("queued attach candidate = %+v, want %+v", got, candidate)
		}
	})

	t.Run("mapping covered by an existing stop is queued without another lease", func(t *testing.T) {
		candidate := candidate
		candidate.stopStartedNS = 9012
		worker := &httpUprobeWorker{attachCandidates: make(chan httpUprobeAttachCandidate, 1)}
		kernelIO := &LinuxKernelIO{httpUprobeWorker: worker}

		if err := kernelIO.handleHTTPUprobeAttachCandidate(encodeHTTPUprobeAttachCandidate(t, candidate)); err != nil {
			t.Fatalf("handleHTTPUprobeAttachCandidate: %v", err)
		}
		if got := <-worker.attachCandidates; got != candidate {
			t.Fatalf("queued attach candidate = %+v, want %+v", got, candidate)
		}
		if worker.stopNotEstablished != 0 {
			t.Fatalf("stop-not-established warnings = %d, want 0", worker.stopNotEstablished)
		}
	})
}

func TestHandleHTTPUprobeAttachCandidateDecodeFailureDisablesDiscovery(t *testing.T) {
	kernelIO := &LinuxKernelIO{httpUprobeWorker: &httpUprobeWorker{}}
	if err := kernelIO.handleHTTPUprobeAttachCandidate([]byte{1}); err == nil {
		t.Fatal("expected malformed attach-candidate error")
	}
	if !kernelIO.httpUprobeDiscoveryFailed {
		t.Fatal("malformed attach candidate did not disable discovery")
	}
}

func encodeHTTPUprobeAttachCandidate(t *testing.T, candidate httpUprobeAttachCandidate) KernelSample {
	t.Helper()
	sample := bpfprog.BPFProgramHttpUprobeAttachCandidateSample{
		Kind:          SampleKindHTTPUprobeAttachCandidate,
		Tgid:          candidate.process.TGID,
		StartBoottime: candidate.process.StartBoottime,
		StopStartedNs: candidate.stopStartedNS,
		StopRequested: boolToUint8(candidate.stopRequested),
		VmStart:       candidate.vmStart,
		VmEnd:         candidate.vmEnd,
		File: bpfprog.BPFProgramFileClassificationKey{
			CtimeSec:  candidate.file.ctimeSec,
			CtimeNsec: candidate.file.ctimeNsec,
		},
	}
	sample.File.MappedFile.DeviceMajor = candidate.file.mappedFile.deviceMajor
	sample.File.MappedFile.DeviceMinor = candidate.file.mappedFile.deviceMinor
	sample.File.MappedFile.Inode = candidate.file.mappedFile.inode
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, sample); err != nil {
		t.Fatalf("encode HTTP uprobe attach candidate: %v", err)
	}
	return buf.Bytes()
}

func boolToUint8(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}
