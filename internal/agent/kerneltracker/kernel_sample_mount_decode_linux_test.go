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

func TestDecodeMountSample(t *testing.T) {
	valid := func() bpfprog.BPFProgramMountSample {
		sample := bpfprog.BPFProgramMountSample{
			Kind:            kernelio.SampleKindMount,
			SourceTruncated: 1,
			TsNs:            1234,
			CgroupId:        5678,
			StartBoottime:   999,
			Tgid:            42,
		}
		copy(sample.SourcePath[:], rightAlignedCString("/real/source"))
		sample.SourceOffset = uint16(len(sample.SourcePath) - len("/real/source") - 1)
		copy(sample.TargetPath[:], rightAlignedCString("/mnt/target"))
		sample.TargetOffset = uint16(len(sample.TargetPath) - len("/mnt/target") - 1)
		return sample
	}

	tests := []struct {
		name       string
		raw        []byte
		want       mountSample
		wantErrSub string
	}{
		{
			name: "valid_mount_sample",
			raw:  encodeMountSample(t, valid()),
			want: mountSample{
				Identity: processIdentity{
					PID:           42,
					StartBoottime: 999,
				},
				CgroupID:        5678,
				TsNs:            1234,
				SourcePath:      "/real/source",
				TargetPath:      "/mnt/target",
				SourceTruncated: true,
			},
		},
		{
			name:       "wrong_size_rejected",
			raw:        []byte{1, 2, 3},
			wantErrSub: "unexpected mount sample size",
		},
		{
			name:       "wrong_kind_rejected",
			raw:        encodeMountSample(t, bpfprog.BPFProgramMountSample{Kind: 99}),
			wantErrSub: "unexpected mount sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeMountSample(test.raw)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeMountSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeMountSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeMountSample() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("decodeMountSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func encodeMountSample(t *testing.T, sample bpfprog.BPFProgramMountSample) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, sample); err != nil {
		t.Fatalf("encode mount sample: %v", err)
	}
	return buf.Bytes()
}

func rightAlignedCString(value string) []int8 {
	out := make([]int8, 1024)
	offset := len(out) - len(value) - 1
	for i := range value {
		out[offset+i] = int8(value[i])
	}
	return out
}
