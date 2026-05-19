//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func TestDecodeForkSample(t *testing.T) {
	t.Parallel()

	validSample := encodeForkSample(t, bpfprog.BPFProgramForkSample{
		Kind:                kernelio.SampleKindFork,
		ChildTgid:           101,
		ChildStartBoottime:  201,
		ParentTgid:          301,
		ParentStartBoottime: 401,
		CgroupId:            501,
		TsNs:                601,
	})
	packedSample := makePackedForkRecordSample()

	tests := []struct {
		name       string
		sample     []byte
		want       forkSample
		wantErrSub string
	}{
		{
			name:   "valid_generated_struct_fixture",
			sample: validSample,
			want: forkSample{
				Child:         processIdentity{PID: 101, StartBoottime: 201},
				Parent:        processIdentity{PID: 301, StartBoottime: 401},
				ChildCgroupID: 501,
				TsNs:          601,
			},
		},
		{
			name:   "valid_packed_fixture",
			sample: packedSample,
			want: forkSample{
				Child:         processIdentity{PID: 101, StartBoottime: 201},
				Parent:        processIdentity{PID: 301, StartBoottime: 401},
				ChildCgroupID: 501,
				TsNs:          601,
			},
		},
		{
			name:       "unexpected_size",
			sample:     validSample[:len(validSample)-1],
			wantErrSub: "unexpected fork sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     encodeForkSample(t, bpfprog.BPFProgramForkSample{Kind: 9}),
			wantErrSub: "unexpected fork sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeForkSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeForkSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeForkSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeForkSample() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("decodeForkSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func encodeForkSample(t *testing.T, sample bpfprog.BPFProgramForkSample) []byte {
	t.Helper()

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}

	return buffer.Bytes()
}

func makePackedForkRecordSample() []byte {
	sample := make([]byte, 48)

	binary.LittleEndian.PutUint32(sample[0:4], kernelio.SampleKindFork)
	binary.LittleEndian.PutUint32(sample[4:8], 0)
	binary.LittleEndian.PutUint64(sample[8:16], 601)
	binary.LittleEndian.PutUint64(sample[16:24], 501)
	binary.LittleEndian.PutUint64(sample[24:32], 201)
	binary.LittleEndian.PutUint64(sample[32:40], 401)
	binary.LittleEndian.PutUint32(sample[40:44], 101)
	binary.LittleEndian.PutUint32(sample[44:48], 301)

	return sample
}

func TestDecodeExecSample(t *testing.T) {
	t.Parallel()

	var execPath [512]int8
	for index, value := range []byte("/usr/bin/echo") {
		execPath[index] = int8(value)
	}

	var argvBlob [2048]int8
	for index, value := range []byte{'e', 'c', 'h', 'o', 0, 'h', 'i', 0} {
		argvBlob[index] = int8(value)
	}

	validSample := encodeExecSample(t, bpfprog.BPFProgramExecSample{
		Kind:          kernelio.SampleKindExec,
		ArgvTruncated: 1,
		ArgvFaulted:   1,
		TsNs:          701,
		CgroupId:      801,
		StartBoottime: 901,
		Tgid:          1001,
		IsMemfd:       1,
		Argc:          2,
		ArgvBlobLen:   8,
		ExecPath:      execPath,
		ArgvBlob:      argvBlob,
	})

	memfdOffSample := encodeExecSample(t, bpfprog.BPFProgramExecSample{
		Kind:          kernelio.SampleKindExec,
		TsNs:          701,
		CgroupId:      801,
		StartBoottime: 901,
		Tgid:          1001,
		IsMemfd:       0,
		Argc:          2,
		ArgvBlobLen:   8,
		ExecPath:      execPath,
		ArgvBlob:      argvBlob,
	})

	tests := []struct {
		name       string
		sample     []byte
		want       execSample
		wantErrSub string
	}{
		{
			name:   "valid",
			sample: validSample,
			want: execSample{
				Identity:      processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID:      801,
				TsNs:          701,
				ExecPath:      "/usr/bin/echo",
				Argc:          2,
				ArgvBlob:      []byte{'e', 'c', 'h', 'o', 0, 'h', 'i', 0},
				ArgvTruncated: true,
				ArgvFaulted:   true,
				IsMemfd:       true,
			},
		},
		{
			name:   "memfd_off",
			sample: memfdOffSample,
			want: execSample{
				Identity: processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID: 801,
				TsNs:     701,
				ExecPath: "/usr/bin/echo",
				Argc:     2,
				ArgvBlob: []byte{'e', 'c', 'h', 'o', 0, 'h', 'i', 0},
				IsMemfd:  false,
			},
		},
		{
			name: "argv_blob_len_out_of_range",
			sample: encodeExecSample(t, bpfprog.BPFProgramExecSample{
				Kind:        kernelio.SampleKindExec,
				ArgvBlobLen: 2049,
			}),
			wantErrSub: "read exec argv blob",
		},
		{
			name:       "unexpected_size",
			sample:     validSample[:len(validSample)-1],
			wantErrSub: "unexpected exec sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     encodeExecSample(t, bpfprog.BPFProgramExecSample{Kind: 9}),
			wantErrSub: "unexpected exec sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeExecSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeExecSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeExecSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeExecSample() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("decodeExecSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDecodeExecSampleArgvBlobLenBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("zero length", func(t *testing.T) {
		t.Parallel()

		got, err := decodeExecSample(encodeExecSample(t, bpfprog.BPFProgramExecSample{
			Kind: kernelio.SampleKindExec,
			Argc: 1<<31 + 7,
		}))
		if err != nil {
			t.Fatalf("decodeExecSample() error = %v", err)
		}
		if len(got.ArgvBlob) != 0 {
			t.Fatalf("argv blob len = %d, want 0", len(got.ArgvBlob))
		}
		if got.Argc != 1<<31+7 {
			t.Fatalf("argc = %d, want %d", got.Argc, uint32(1<<31+7))
		}
	})

	t.Run("exact max length", func(t *testing.T) {
		t.Parallel()

		var argvBlob [2048]int8
		for index := range argvBlob {
			argvBlob[index] = int8(byte(index%251) + 1)
		}

		got, err := decodeExecSample(encodeExecSample(t, bpfprog.BPFProgramExecSample{
			Kind:        kernelio.SampleKindExec,
			Argc:        1,
			ArgvBlobLen: uint32(len(argvBlob)),
			ArgvBlob:    argvBlob,
		}))
		if err != nil {
			t.Fatalf("decodeExecSample() error = %v", err)
		}
		if len(got.ArgvBlob) != len(argvBlob) {
			t.Fatalf("argv blob len = %d, want %d", len(got.ArgvBlob), len(argvBlob))
		}
		for index, value := range got.ArgvBlob {
			want := byte(index%251) + 1
			if value != want {
				t.Fatalf("argv blob[%d] = %d, want %d", index, value, want)
			}
		}
	})

	t.Run("ignores non-zero tail after declared length", func(t *testing.T) {
		t.Parallel()

		var argvBlob [2048]int8
		for index, value := range []byte("cmd\x00arg\x00") {
			argvBlob[index] = int8(value)
		}
		for index := 8; index < len(argvBlob); index++ {
			argvBlob[index] = int8('x')
		}

		got, err := decodeExecSample(encodeExecSample(t, bpfprog.BPFProgramExecSample{
			Kind:        kernelio.SampleKindExec,
			Argc:        2,
			ArgvBlobLen: 8,
			ArgvBlob:    argvBlob,
		}))
		if err != nil {
			t.Fatalf("decodeExecSample() error = %v", err)
		}
		if got.Argc != 2 {
			t.Fatalf("argc = %d, want 2", got.Argc)
		}
		if got := got.ArgvBlob; !reflect.DeepEqual(got, []byte("cmd\x00arg\x00")) {
			t.Fatalf("argv blob = %#v, want declared prefix only", got)
		}
	})

	t.Run("out of range length", func(t *testing.T) {
		t.Parallel()

		_, err := decodeExecSample(encodeExecSample(t, bpfprog.BPFProgramExecSample{
			Kind:        kernelio.SampleKindExec,
			ArgvBlobLen: 2049,
		}))
		if err == nil {
			t.Fatal("decodeExecSample() error = nil, want argv blob length error")
		}
		if !strings.Contains(err.Error(), "read exec argv blob") {
			t.Fatalf("decodeExecSample() error = %q, want argv blob length error", err)
		}
	})
}

func encodeExecSample(t *testing.T, sample bpfprog.BPFProgramExecSample) []byte {
	t.Helper()

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}

	return buffer.Bytes()
}
