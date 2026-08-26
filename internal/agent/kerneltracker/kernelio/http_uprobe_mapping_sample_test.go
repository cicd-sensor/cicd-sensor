//go:build linux

package kernelio

import (
	"bytes"
	"encoding/binary"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
)

func TestDecodeHTTPUprobeMappingSample(t *testing.T) {
	want := httpUprobeMapping{
		tgid:    1234,
		vmStart: 0x400000,
		vmEnd:   0x401000,
		file: fileClassificationKey{
			mappedFile: mappedFileIdentity{deviceMajor: 8, deviceMinor: 1, inode: 99},
			ctimeSec:   123,
			ctimeNsec:  456,
		},
	}
	raw := encodeHTTPUprobeMappingSample(t, want)

	t.Run("valid mapping preserves the BPF ABI", func(t *testing.T) {
		got, err := decodeHTTPUprobeMappingSample(raw)
		if err != nil {
			t.Fatalf("decodeHTTPUprobeMappingSample: %v", err)
		}
		if got != want {
			t.Fatalf("mapping = %+v, want %+v", got, want)
		}
	})

	t.Run("short sample cannot be partially decoded", func(t *testing.T) {
		if _, err := decodeHTTPUprobeMappingSample(raw[:len(raw)-1]); err == nil {
			t.Fatal("decodeHTTPUprobeMappingSample succeeded for a short sample")
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

func TestHandleHTTPUprobeMappingSample(t *testing.T) {
	mapping := httpUprobeMapping{tgid: 1234, vmStart: 0x400000, vmEnd: 0x401000}

	t.Run("ordinary security sample stays on the caller path", func(t *testing.T) {
		kernelIO := &LinuxKernelIO{}
		handled, err := kernelIO.handleHTTPUprobeMappingSample([]byte{1, 0, 0, 0})
		if err != nil || handled {
			t.Fatalf("handled = %v, err = %v, want false, nil", handled, err)
		}
	})

	t.Run("mapping sample is queued without entering KernelTracker", func(t *testing.T) {
		discovery := &httpUprobeDiscovery{mappingRequests: make(chan httpUprobeMapping, 1)}
		kernelIO := &LinuxKernelIO{httpUprobeDiscovery: discovery}
		handled, err := kernelIO.handleHTTPUprobeMappingSample(encodeHTTPUprobeMappingSample(t, mapping))
		if err != nil || !handled {
			t.Fatalf("handled = %v, err = %v, want true, nil", handled, err)
		}
		if got := <-discovery.mappingRequests; got != mapping {
			t.Fatalf("queued mapping = %+v, want %+v", got, mapping)
		}
	})

	t.Run("disabled discovery consumes its private control sample", func(t *testing.T) {
		kernelIO := &LinuxKernelIO{}
		handled, err := kernelIO.handleHTTPUprobeMappingSample(encodeHTTPUprobeMappingSample(t, mapping))
		if err != nil || !handled {
			t.Fatalf("handled = %v, err = %v, want true, nil", handled, err)
		}
	})
}

func encodeHTTPUprobeMappingSample(t *testing.T, mapping httpUprobeMapping) KernelSample {
	t.Helper()
	sample := bpfprog.BPFProgramHttpUprobeMappingSample{
		Kind:    SampleKindHTTPUprobeMapping,
		Tgid:    mapping.tgid,
		VmStart: mapping.vmStart,
		VmEnd:   mapping.vmEnd,
		File: bpfprog.BPFProgramFileClassificationKey{
			CtimeSec:  mapping.file.ctimeSec,
			CtimeNsec: mapping.file.ctimeNsec,
		},
	}
	sample.File.MappedFile.DeviceMajor = mapping.file.mappedFile.deviceMajor
	sample.File.MappedFile.DeviceMinor = mapping.file.mappedFile.deviceMinor
	sample.File.MappedFile.Inode = mapping.file.mappedFile.inode
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, sample); err != nil {
		t.Fatalf("encode HTTP uprobe mapping sample: %v", err)
	}
	return buf.Bytes()
}
