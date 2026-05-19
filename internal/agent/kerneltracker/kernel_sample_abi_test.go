//go:build kernel_sample_abi && linux

package kerneltracker

import (
	"reflect"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

var kernelSampleABISize = map[string]uintptr{
	"CgroupAttachSample":      40,
	"CgroupMkdirSample":       544,
	"CgroupRmdirSample":       24,
	"DnsSample":               584,
	"ExecSample":              2608,
	"FileLinkSample":          2096,
	"FileMoveSample":          2096,
	"FileOpenSample":          1064,
	"FileRemoveSample":        1064,
	"ForkSample":              48,
	"NetV4Sample":             48,
	"NetV6Sample":             64,
	"UnixSocketConnectSample": 1176,
}

func TestKernelSampleABISizes(t *testing.T) {
	cases := map[string]reflect.Type{
		"CgroupAttachSample":      reflect.TypeOf(bpfprog.BPFProgramCgroupAttachSample{}),
		"CgroupMkdirSample":       reflect.TypeOf(bpfprog.BPFProgramCgroupMkdirSample{}),
		"CgroupRmdirSample":       reflect.TypeOf(bpfprog.BPFProgramCgroupRmdirSample{}),
		"DnsSample":               reflect.TypeOf(bpfprog.BPFProgramDnsSample{}),
		"ExecSample":              reflect.TypeOf(bpfprog.BPFProgramExecSample{}),
		"FileLinkSample":          reflect.TypeOf(bpfprog.BPFProgramFileLinkSample{}),
		"FileMoveSample":          reflect.TypeOf(bpfprog.BPFProgramFileMoveSample{}),
		"FileOpenSample":          reflect.TypeOf(bpfprog.BPFProgramFileOpenSample{}),
		"FileRemoveSample":        reflect.TypeOf(bpfprog.BPFProgramFileRemoveSample{}),
		"ForkSample":              reflect.TypeOf(bpfprog.BPFProgramForkSample{}),
		"NetV4Sample":             reflect.TypeOf(bpfprog.BPFProgramNetV4Sample{}),
		"NetV6Sample":             reflect.TypeOf(bpfprog.BPFProgramNetV6Sample{}),
		"UnixSocketConnectSample": reflect.TypeOf(bpfprog.BPFProgramUnixSocketConnectSample{}),
	}

	for name, typ := range cases {
		want, ok := kernelSampleABISize[name]
		if !ok {
			t.Fatalf("baseline missing: %s", name)
		}
		if got := typ.Size(); got != want {
			t.Errorf("%s sizeof: got %d want %d", name, got, want)
		}
	}
}

func TestKernelSampleABIKindField(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(bpfprog.BPFProgramCgroupAttachSample{}),
		reflect.TypeOf(bpfprog.BPFProgramCgroupMkdirSample{}),
		reflect.TypeOf(bpfprog.BPFProgramCgroupRmdirSample{}),
		reflect.TypeOf(bpfprog.BPFProgramDnsSample{}),
		reflect.TypeOf(bpfprog.BPFProgramExecSample{}),
		reflect.TypeOf(bpfprog.BPFProgramFileLinkSample{}),
		reflect.TypeOf(bpfprog.BPFProgramFileMoveSample{}),
		reflect.TypeOf(bpfprog.BPFProgramFileOpenSample{}),
		reflect.TypeOf(bpfprog.BPFProgramFileRemoveSample{}),
		reflect.TypeOf(bpfprog.BPFProgramForkSample{}),
		reflect.TypeOf(bpfprog.BPFProgramNetV4Sample{}),
		reflect.TypeOf(bpfprog.BPFProgramNetV6Sample{}),
		reflect.TypeOf(bpfprog.BPFProgramUnixSocketConnectSample{}),
	}

	for _, typ := range types {
		kind, ok := typ.FieldByName("Kind")
		if !ok {
			t.Errorf("%s: Kind field missing", typ)
			continue
		}
		if kind.Offset != 0 {
			t.Errorf("%s: Kind field offset = %d, want 0", typ, kind.Offset)
		}
		if kind.Type.Kind() != reflect.Uint32 {
			t.Errorf("%s: Kind field type = %s, want uint32", typ, kind.Type.Kind())
		}
	}
}

func TestKernelSampleKindValues(t *testing.T) {
	cases := map[uint32]uint32{
		kernelio.SampleKindFork:              1,
		kernelio.SampleKindCgroupMkdir:       2,
		kernelio.SampleKindCgroupAttach:      3,
		kernelio.SampleKindCgroupRmdir:       4,
		kernelio.SampleKindExec:              5,
		kernelio.SampleKindNetworkConnectV4:  6,
		kernelio.SampleKindNetworkConnectV6:  7,
		kernelio.SampleKindFileOpen:          8,
		kernelio.SampleKindFileRemove:        9,
		kernelio.SampleKindFileMove:          10,
		kernelio.SampleKindFileLink:          11,
		kernelio.SampleKindDNS:               12,
		kernelio.SampleKindUnixSocketConnect: 13,
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("sample kind value: got %d want %d", got, want)
		}
	}
}
