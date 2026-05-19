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

func TestDecodeCgroupMkdirSample(t *testing.T) {
	t.Parallel()

	validRecord := bpfprog.BPFProgramCgroupMkdirSample{
		Kind:           kernelio.SampleKindCgroupMkdir,
		StagingMatched: 1,
		CgroupId:       11,
		ParentCgroupId: 7,
		TsNs:           99,
	}
	for index, value := range []byte("/test/job") {
		validRecord.Path[index] = int8(value)
	}

	validSample := encodeCgroupMkdirSample(t, validRecord)

	tests := []struct {
		name       string
		sample     []byte
		want       cgroupMkdirSample
		wantErrSub string
	}{
		{
			name:   "valid",
			sample: validSample,
			want: cgroupMkdirSample{
				CgroupID:       11,
				ParentCgroupID: 7,
				CgroupPath:     "/test/job",
				TsNs:           99,
				StagingMatched: true,
			},
		},
		{
			name:       "unexpected_size",
			sample:     validSample[:len(validSample)-1],
			wantErrSub: "unexpected cgroup mkdir sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     encodeCgroupMkdirSample(t, bpfprog.BPFProgramCgroupMkdirSample{Kind: 9}),
			wantErrSub: "unexpected cgroup mkdir sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeCgroupMkdirSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeCgroupMkdirSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeCgroupMkdirSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeCgroupMkdirSample() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("decodeCgroupMkdirSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDecodeCgroupAttachSample(t *testing.T) {
	t.Parallel()

	validSample := encodeCgroupAttachSample(t, bpfprog.BPFProgramCgroupAttachSample{
		Kind:                kernelio.SampleKindCgroupAttach,
		TsNs:                201,
		SourceCgroupId:      301,
		DestinationCgroupId: 401,
		Tgid:                501,
	})

	tests := []struct {
		name       string
		sample     []byte
		want       cgroupAttachSample
		wantErrSub string
	}{
		{
			name:   "valid",
			sample: validSample,
			want: cgroupAttachSample{
				Tgid:                501,
				SourceCgroupID:      301,
				DestinationCgroupID: 401,
				TsNs:                201,
			},
		},
		{
			name:       "unexpected_size",
			sample:     validSample[:len(validSample)-1],
			wantErrSub: "unexpected cgroup attach sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     encodeCgroupAttachSample(t, bpfprog.BPFProgramCgroupAttachSample{Kind: 9}),
			wantErrSub: "unexpected cgroup attach sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeCgroupAttachSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeCgroupAttachSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeCgroupAttachSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeCgroupAttachSample() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("decodeCgroupAttachSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDecodeCgroupRmdirSample(t *testing.T) {
	t.Parallel()

	validSample := encodeCgroupRmdirSample(t, bpfprog.BPFProgramCgroupRmdirSample{
		Kind:     kernelio.SampleKindCgroupRmdir,
		CgroupId: 11,
		TsNs:     99,
	})

	tests := []struct {
		name       string
		sample     []byte
		want       cgroupRmdirSample
		wantErrSub string
	}{
		{
			name:   "valid",
			sample: validSample,
			want: cgroupRmdirSample{
				CgroupID: 11,
				TsNs:     99,
			},
		},
		{
			name:       "unexpected_size",
			sample:     validSample[:len(validSample)-1],
			wantErrSub: "unexpected cgroup rmdir sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     encodeCgroupRmdirSample(t, bpfprog.BPFProgramCgroupRmdirSample{Kind: 9}),
			wantErrSub: "unexpected cgroup rmdir sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeCgroupRmdirSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeCgroupRmdirSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeCgroupRmdirSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeCgroupRmdirSample() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("decodeCgroupRmdirSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func encodeCgroupMkdirSample(t *testing.T, sample bpfprog.BPFProgramCgroupMkdirSample) []byte {
	t.Helper()

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}

	return buffer.Bytes()
}

func encodeCgroupAttachSample(t *testing.T, sample bpfprog.BPFProgramCgroupAttachSample) []byte {
	t.Helper()

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}

	return buffer.Bytes()
}

func encodeCgroupRmdirSample(t *testing.T, sample bpfprog.BPFProgramCgroupRmdirSample) []byte {
	t.Helper()

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}

	return buffer.Bytes()
}
