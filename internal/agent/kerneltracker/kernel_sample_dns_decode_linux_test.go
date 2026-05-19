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

func TestDecodeDNSSample(t *testing.T) {
	t.Parallel()

	buildSample := func(t *testing.T, kind uint32, payloadLen uint32) []byte {
		t.Helper()

		sample := bpfprog.BPFProgramDnsSample{
			Kind:          kind,
			Source:        0,
			Family:        2,
			Dport:         53,
			PayloadLen:    payloadLen,
			TsNs:          701,
			CgroupId:      801,
			StartBoottime: 901,
			Tgid:          1001,
			DaddrV4:       [4]uint8{1, 1, 1, 1},
		}
		// First few bytes of a synthetic DNS query so the parse_test
		// asserts payload trimming works (we never actually decode the
		// DNS message in this test — that lives in event_dns_test.go).
		copy(sample.Payload[:], []byte{0x12, 0x34, 0x01, 0x00})

		var buffer bytes.Buffer
		if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
			t.Fatalf("binary.Write() error = %v", err)
		}
		return buffer.Bytes()
	}

	tests := []struct {
		name       string
		sample     []byte
		want       dnsSample
		wantErrSub string
	}{
		{
			name:   "valid",
			sample: buildSample(t, kernelio.SampleKindDNS, 4),
			want: dnsSample{
				Identity:   processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID:   801,
				TsNs:       701,
				Source:     DNSSourceUDP,
				Family:     2,
				Dport:      53,
				DaddrV4:    [4]byte{1, 1, 1, 1},
				DaddrV6:    [16]byte{},
				Payload:    []byte{0x12, 0x34, 0x01, 0x00},
				PayloadLen: 4,
			},
		},
		{
			name:       "unexpected_size",
			sample:     buildSample(t, kernelio.SampleKindDNS, 4)[:binary.Size(bpfprog.BPFProgramDnsSample{})-1],
			wantErrSub: "unexpected dns sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     buildSample(t, 99, 4),
			wantErrSub: "unexpected dns sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeDNSSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeDNSSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeDNSSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeDNSSample() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("decodeDNSSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}
