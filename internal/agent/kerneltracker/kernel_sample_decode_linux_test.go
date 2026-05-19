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

func TestDecodeKernelSampleRejectsShortRecord(t *testing.T) {
	t.Parallel()

	if _, err := decodeKernelSample(kernelio.KernelSample{1, 2, 3}); err == nil {
		t.Fatal("decodeKernelSample short record error = nil, want error")
	}
}

func TestDecodeKernelSampleRejectsUnknownKind(t *testing.T) {
	t.Parallel()

	sample := make([]byte, 4)
	binary.LittleEndian.PutUint32(sample, 0xffff_ffff)

	if _, err := decodeKernelSample(sample); err == nil {
		t.Fatal("decodeKernelSample unknown kind error = nil, want error")
	}
}

func TestDecodeKernelSampleDispatchesSampleKinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		sample kernelio.KernelSample
		want   decodedKernelSample
	}{
		{
			name:   "fork",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramForkSample{Kind: kernelio.SampleKindFork}),
			want:   forkSample{},
		},
		{
			name:   "cgroup_mkdir",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramCgroupMkdirSample{Kind: kernelio.SampleKindCgroupMkdir}),
			want:   cgroupMkdirSample{},
		},
		{
			name:   "cgroup_attach_sample",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramCgroupAttachSample{Kind: kernelio.SampleKindCgroupAttach}),
			want:   cgroupAttachSample{},
		},
		{
			name:   "cgroup_rmdir",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramCgroupRmdirSample{Kind: kernelio.SampleKindCgroupRmdir}),
			want:   cgroupRmdirSample{},
		},
		{
			name:   "exec",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramExecSample{Kind: kernelio.SampleKindExec}),
			want:   execSample{},
		},
		{
			name:   "network_v4",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramNetV4Sample{Kind: kernelio.SampleKindNetworkConnectV4}),
			want:   netConnectV4Sample{},
		},
		{
			name:   "network_v6",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramNetV6Sample{Kind: kernelio.SampleKindNetworkConnectV6}),
			want:   netConnectV6Sample{},
		},
		{
			name:   "file_open",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramFileOpenSample{Kind: kernelio.SampleKindFileOpen}),
			want:   fileOpenSample{},
		},
		{
			name:   "file_remove",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramFileRemoveSample{Kind: kernelio.SampleKindFileRemove}),
			want:   fileRemoveSample{},
		},
		{
			name:   "file_move",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramFileMoveSample{Kind: kernelio.SampleKindFileMove}),
			want:   fileMoveSample{},
		},
		{
			name:   "file_link",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramFileLinkSample{Kind: kernelio.SampleKindFileLink}),
			want:   fileLinkSample{},
		},
		{
			name:   "dns",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramDnsSample{Kind: kernelio.SampleKindDNS}),
			want:   dnsSample{},
		},
		{
			name:   "unix_socket_connect",
			sample: encodeDispatchSample(t, bpfprog.BPFProgramUnixSocketConnectSample{Kind: kernelio.SampleKindUnixSocketConnect}),
			want:   unixSocketConnectSample{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeKernelSample(test.sample)
			if err != nil {
				t.Fatalf("decodeKernelSample: %v", err)
			}
			if reflect.TypeOf(got) != reflect.TypeOf(test.want) {
				t.Fatalf("decodeKernelSample() = %T, want %T", got, test.want)
			}
		})
	}
}

func encodeDispatchSample(t *testing.T, record any) kernelio.KernelSample {
	t.Helper()

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, record); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}
	return kernelio.KernelSample(buffer.Bytes())
}

func TestCString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []int8
		want string
	}{
		{name: "stops at first nul", data: []int8{'a', 'b', 0, 'c'}, want: "ab"},
		{name: "empty at first nul", data: []int8{0, 'a'}, want: ""},
		{name: "whole buffer without nul", data: []int8{'x', 'y'}, want: "xy"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := cString(test.data); got != test.want {
				t.Fatalf("cString() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCBytes(t *testing.T) {
	t.Parallel()

	got, err := cBytes([]int8{'a', 0, 'b', 'c'}, 3)
	if err != nil {
		t.Fatalf("cBytes: %v", err)
	}
	if string(got) != "a\x00b" {
		t.Fatalf("cBytes() = %q, want %q", string(got), "a\x00b")
	}

	if _, err := cBytes([]int8{'a'}, 2); err == nil || !strings.Contains(err.Error(), "exceeds C char buffer size") {
		t.Fatalf("cBytes oversized error = %v, want buffer size error", err)
	}
}

func TestPathFromBuffer(t *testing.T) {
	t.Parallel()

	buf := []int8{'x', 'x', '/', 't', 'm', 'p', 0, 'y'}
	if got := pathFromBuffer(buf, 2); got != "/tmp" {
		t.Fatalf("pathFromBuffer valid offset = %q, want /tmp", got)
	}
	if got := pathFromBuffer(buf, uint16(len(buf))); got != "" {
		t.Fatalf("pathFromBuffer out-of-range offset = %q, want empty", got)
	}
}
