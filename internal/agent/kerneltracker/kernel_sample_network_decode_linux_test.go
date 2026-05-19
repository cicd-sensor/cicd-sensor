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

func TestDecodeNetConnectV4Sample(t *testing.T) {
	t.Parallel()

	buildSample := func(t *testing.T, kind uint32) []byte {
		t.Helper()

		return encodeNetV4Sample(t, bpfprog.BPFProgramNetV4Sample{
			Kind:          kind,
			Protocol:      6,
			Blocked:       1,
			TsNs:          701,
			CgroupId:      801,
			StartBoottime: 901,
			Tgid:          1001,
			RemoteIp:      [4]uint8{127, 0, 0, 1},
			RemotePort:    443,
		})
	}

	tests := []struct {
		name       string
		sample     []byte
		want       netConnectV4Sample
		wantErrSub string
	}{
		{
			name:   "valid",
			sample: buildSample(t, kernelio.SampleKindNetworkConnectV4),
			want: netConnectV4Sample{
				Identity:   processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID:   801,
				RemoteIPv4: [4]byte{127, 0, 0, 1},
				Port:       443,
				Protocol:   6,
				TsNs:       701,
				Blocked:    true,
			},
		},
		{
			name:       "unexpected_size",
			sample:     buildSample(t, kernelio.SampleKindNetworkConnectV4)[:binary.Size(bpfprog.BPFProgramNetV4Sample{})-1],
			wantErrSub: "unexpected net connect v4 sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     buildSample(t, 99),
			wantErrSub: "unexpected net connect v4 sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeNetConnectV4Sample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeNetConnectV4Sample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeNetConnectV4Sample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeNetConnectV4Sample() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("decodeNetConnectV4Sample() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDecodeNetConnectV6Sample(t *testing.T) {
	t.Parallel()

	buildSample := func(t *testing.T, kind uint32) []byte {
		t.Helper()

		return encodeNetV6Sample(t, bpfprog.BPFProgramNetV6Sample{
			Kind:          kind,
			Protocol:      17,
			Blocked:       0,
			TsNs:          702,
			CgroupId:      802,
			StartBoottime: 902,
			Tgid:          1002,
			RemoteIp:      [16]uint8{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			RemotePort:    53,
		})
	}

	tests := []struct {
		name       string
		sample     []byte
		want       netConnectV6Sample
		wantErrSub string
	}{
		{
			name:   "valid",
			sample: buildSample(t, kernelio.SampleKindNetworkConnectV6),
			want: netConnectV6Sample{
				Identity:   processIdentity{PID: 1002, StartBoottime: 902},
				CgroupID:   802,
				RemoteIPv6: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				Port:       53,
				Protocol:   17,
				TsNs:       702,
				Blocked:    false,
			},
		},
		{
			name:       "unexpected_size",
			sample:     buildSample(t, kernelio.SampleKindNetworkConnectV6)[:binary.Size(bpfprog.BPFProgramNetV6Sample{})-1],
			wantErrSub: "unexpected net connect v6 sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     buildSample(t, 99),
			wantErrSub: "unexpected net connect v6 sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeNetConnectV6Sample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeNetConnectV6Sample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeNetConnectV6Sample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeNetConnectV6Sample() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("decodeNetConnectV6Sample() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func encodeNetV4Sample(t *testing.T, sample bpfprog.BPFProgramNetV4Sample) []byte {
	t.Helper()

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}

	return buffer.Bytes()
}

func encodeNetV6Sample(t *testing.T, sample bpfprog.BPFProgramNetV6Sample) []byte {
	t.Helper()

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
		t.Fatalf("binary.Write() error = %v", err)
	}

	return buffer.Bytes()
}
