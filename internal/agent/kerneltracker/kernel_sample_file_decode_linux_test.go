//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func TestDecodeFileOpenSample(t *testing.T) {
	t.Parallel()

	buildSample := func(t *testing.T, isWrite, isRead, truncated uint8, path string) []byte {
		t.Helper()
		sample := bpfprog.BPFProgramFileOpenSample{
			Kind:          kernelio.SampleKindFileOpen,
			IsWrite:       isWrite,
			IsRead:        isRead,
			PathTruncated: truncated,
			TsNs:          701,
			CgroupId:      801,
			StartBoottime: 901,
			Tgid:          1001,
			Flags:         123,
		}
		for index, value := range []byte(path) {
			sample.Path[index] = int8(value)
		}
		return encodeFileOpenSample(t, sample)
	}

	rdwrSample := buildSample(t, 1, 1, 1, "/tmp/example.go")
	readOnlySample := buildSample(t, 0, 1, 0, "/tmp/example.go")
	writeOnlySample := buildSample(t, 1, 0, 0, "/tmp/example.go")

	baseWant := func(isWrite, isRead, truncated bool) fileOpenSample {
		return fileOpenSample{
			Identity:      processIdentity{PID: 1001, StartBoottime: 901},
			CgroupID:      801,
			TsNs:          701,
			Path:          "/tmp/example.go",
			Flags:         123,
			IsWrite:       isWrite,
			IsRead:        isRead,
			PathTruncated: truncated,
		}
	}

	tests := []struct {
		name       string
		sample     []byte
		want       fileOpenSample
		wantErrSub string
	}{
		{
			name:   "rdwr",
			sample: rdwrSample,
			want:   baseWant(true, true, true),
		},
		{
			name:   "read_only",
			sample: readOnlySample,
			want:   baseWant(false, true, false),
		},
		{
			name:   "write_only",
			sample: writeOnlySample,
			want:   baseWant(true, false, false),
		},
		{
			name:       "unexpected_size",
			sample:     rdwrSample[:len(rdwrSample)-1],
			wantErrSub: "unexpected file open sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     encodeFileOpenSample(t, bpfprog.BPFProgramFileOpenSample{Kind: 99}),
			wantErrSub: "unexpected file open sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeFileOpenSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeFileOpenSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeFileOpenSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeFileOpenSample() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("decodeFileOpenSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func encodeFileOpenSample(t *testing.T, sample bpfprog.BPFProgramFileOpenSample) []byte {
	t.Helper()

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}

	return buffer.Bytes()
}

func encodeFileRemoveSample(t *testing.T, sample bpfprog.BPFProgramFileRemoveSample) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}
	return buffer.Bytes()
}

func encodeFileMoveSample(t *testing.T, sample bpfprog.BPFProgramFileMoveSample) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}
	return buffer.Bytes()
}

func encodeFileLinkSample(t *testing.T, sample bpfprog.BPFProgramFileLinkSample) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}
	return buffer.Bytes()
}

// writeRightAlignedPath places `s` into buf right-aligned (mirroring the
// kernel-side resolve_dentry_path output) and returns the start byte offset.
// The trailing NUL falls inside the buf because every path field has at
// least one byte of headroom for it.

func writeRightAlignedPath(buf []int8, s string) uint16 {
	for i := range buf {
		buf[i] = 0
	}
	if s == "" {
		return uint16(len(buf) - 1)
	}
	off := len(buf) - 1 - len(s)
	if off < 0 {
		off = 0
	}
	for i, b := range []byte(s) {
		if off+i >= len(buf)-1 {
			break
		}
		buf[off+i] = int8(b)
	}
	return uint16(off)
}

// writeLeftAlignedPath places `s` into buf left-aligned (mirroring symlink
// existing_path emission). Returns 0 for the offset.

func writeLeftAlignedPath(buf []int8, s string) uint16 {
	for i := range buf {
		buf[i] = 0
	}
	for i, b := range []byte(s) {
		if i >= len(buf)-1 {
			break
		}
		buf[i] = int8(b)
	}
	return 0
}

func TestDecodeFileRemoveSample(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, isFolder, truncated uint8, p string) []byte {
		t.Helper()
		sample := bpfprog.BPFProgramFileRemoveSample{
			Kind:          kernelio.SampleKindFileRemove,
			IsFolder:      isFolder,
			PathTruncated: truncated,
			TsNs:          701,
			CgroupId:      801,
			StartBoottime: 901,
			Tgid:          1001,
		}
		sample.PathOffset = writeRightAlignedPath(sample.Path[:], p)
		return encodeFileRemoveSample(t, sample)
	}

	want := func(isFolder, truncated bool, p string) fileRemoveSample {
		return fileRemoveSample{
			Identity:      processIdentity{PID: 1001, StartBoottime: 901},
			CgroupID:      801,
			TsNs:          701,
			Path:          p,
			IsFolder:      isFolder,
			PathTruncated: truncated,
		}
	}

	tests := []struct {
		name       string
		sample     []byte
		want       fileRemoveSample
		wantErrSub string
	}{
		{name: "unlink_secret", sample: build(t, 0, 0, "/etc/shadow"), want: want(false, false, "/etc/shadow")},
		{name: "rmdir_truncated", sample: build(t, 1, 1, "/var/log/journal"), want: want(true, true, "/var/log/journal")},
		{name: "unexpected_size", sample: build(t, 0, 0, "/x")[:10], wantErrSub: "unexpected file remove sample size"},
		{name: "unexpected_kind", sample: encodeFileRemoveSample(t, bpfprog.BPFProgramFileRemoveSample{Kind: 99}), wantErrSub: "unexpected file remove sample kind"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeFileRemoveSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("err = %v, want substring %q", err, test.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != test.want {
				t.Fatalf("got = %#v, want = %#v", got, test.want)
			}
		})
	}
}

func TestDecodeFileMoveSample(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, fromTrunc, toTrunc uint8, from, to string) []byte {
		t.Helper()
		sample := bpfprog.BPFProgramFileMoveSample{
			Kind:          kernelio.SampleKindFileMove,
			FromTruncated: fromTrunc,
			ToTruncated:   toTrunc,
			TsNs:          702,
			CgroupId:      802,
			StartBoottime: 902,
			Tgid:          1002,
		}
		sample.FromOffset = writeRightAlignedPath(sample.FromPath[:], from)
		sample.ToOffset = writeRightAlignedPath(sample.ToPath[:], to)
		return encodeFileMoveSample(t, sample)
	}

	got, err := decodeFileMoveSample(build(t, 0, 0, "/tmp/payload.bin", "/run/init"))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := fileMoveSample{
		Identity:      processIdentity{PID: 1002, StartBoottime: 902},
		CgroupID:      802,
		TsNs:          702,
		FromPath:      "/tmp/payload.bin",
		ToPath:        "/run/init",
		FromTruncated: false,
		ToTruncated:   false,
	}
	if got != want {
		t.Fatalf("got = %#v, want = %#v", got, want)
	}

	if _, err := decodeFileMoveSample(encodeFileMoveSample(t, bpfprog.BPFProgramFileMoveSample{Kind: 77})); err == nil {
		t.Fatal("expected error for wrong kind")
	}
}

func TestDecodeFileLinkSample(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, isHard, isSym uint8, created, existing string, leftAlignedExisting bool) []byte {
		t.Helper()
		sample := bpfprog.BPFProgramFileLinkSample{
			Kind:          kernelio.SampleKindFileLink,
			IsHardlink:    isHard,
			IsSymlink:     isSym,
			TsNs:          703,
			CgroupId:      803,
			StartBoottime: 903,
			Tgid:          1003,
		}
		sample.CreatedOffset = writeRightAlignedPath(sample.CreatedPath[:], created)
		if leftAlignedExisting {
			sample.ExistingOffset = writeLeftAlignedPath(sample.ExistingPath[:], existing)
		} else {
			sample.ExistingOffset = writeRightAlignedPath(sample.ExistingPath[:], existing)
		}
		return encodeFileLinkSample(t, sample)
	}

	tests := []struct {
		name   string
		sample []byte
		want   fileLinkSample
	}{
		{
			name:   "hardlink_to_shadow",
			sample: build(t, 1, 0, "/tmp/copy", "/etc/shadow", false),
			want: fileLinkSample{
				Identity:     processIdentity{PID: 1003, StartBoottime: 903},
				CgroupID:     803,
				TsNs:         703,
				CreatedPath:  "/tmp/copy",
				ExistingPath: "/etc/shadow",
				IsHardlink:   true,
			},
		},
		{
			name:   "symlink_relative_existing",
			sample: build(t, 0, 1, "/usr/local/bin/curl", "../../tmp/wrap", true),
			want: fileLinkSample{
				Identity:     processIdentity{PID: 1003, StartBoottime: 903},
				CgroupID:     803,
				TsNs:         703,
				CreatedPath:  "/usr/local/bin/curl",
				ExistingPath: "../../tmp/wrap",
				IsSymlink:    true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeFileLinkSample(test.sample)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != test.want {
				t.Fatalf("got = %#v, want = %#v", got, test.want)
			}
		})
	}
}
