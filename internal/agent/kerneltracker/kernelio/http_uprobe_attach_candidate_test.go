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
		tgid:    1234,
		vmStart: 0x400000,
		vmEnd:   0x401000,
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
}

func TestFileClassificationKeyBPFMapABI(t *testing.T) {
	got := binary.Size(fileClassificationKey{})
	want := binary.Size(bpfprog.BPFProgramFileClassificationKey{})
	if got != want {
		t.Fatalf("file classification key size = %d, want BPF map key size %d", got, want)
	}
}

func TestHandleHTTPUprobeAttachCandidate(t *testing.T) {
	candidate := httpUprobeAttachCandidate{tgid: 1234, vmStart: 0x400000, vmEnd: 0x401000}

	t.Run("ordinary security sample stays on the caller path", func(t *testing.T) {
		kernelIO := &LinuxKernelIO{}
		handled, err := kernelIO.handleHTTPUprobeAttachCandidate([]byte{1, 0, 0, 0})
		if err != nil || handled {
			t.Fatalf("handled = %v, err = %v, want false, nil", handled, err)
		}
	})

	t.Run("attach candidate is queued without entering KernelTracker", func(t *testing.T) {
		worker := &httpUprobeWorker{attachCandidates: make(chan httpUprobeAttachCandidate, 1)}
		kernelIO := &LinuxKernelIO{httpUprobeWorker: worker}
		handled, err := kernelIO.handleHTTPUprobeAttachCandidate(encodeHTTPUprobeAttachCandidate(t, candidate))
		if err != nil || !handled {
			t.Fatalf("handled = %v, err = %v, want true, nil", handled, err)
		}
		if got := <-worker.attachCandidates; got != candidate {
			t.Fatalf("queued attach candidate = %+v, want %+v", got, candidate)
		}
	})

	t.Run("disabled worker consumes its private control sample", func(t *testing.T) {
		kernelIO := &LinuxKernelIO{}
		handled, err := kernelIO.handleHTTPUprobeAttachCandidate(encodeHTTPUprobeAttachCandidate(t, candidate))
		if err != nil || !handled {
			t.Fatalf("handled = %v, err = %v, want true, nil", handled, err)
		}
	})
}

func encodeHTTPUprobeAttachCandidate(t *testing.T, candidate httpUprobeAttachCandidate) KernelSample {
	t.Helper()
	sample := bpfprog.BPFProgramHttpUprobeAttachCandidateSample{
		Kind:    SampleKindHTTPUprobeAttachCandidate,
		Tgid:    candidate.tgid,
		VmStart: candidate.vmStart,
		VmEnd:   candidate.vmEnd,
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
