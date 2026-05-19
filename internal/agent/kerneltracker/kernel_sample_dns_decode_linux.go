//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// decodeDNSSample trims the fixed BPF payload buffer to the reported payload length.
func decodeDNSSample(raw []byte) (dnsSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramDnsSample{}) {
		return dnsSample{}, fmt.Errorf("unexpected dns sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramDnsSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return dnsSample{}, fmt.Errorf("read dns sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindDNS {
		return dnsSample{}, fmt.Errorf("unexpected dns sample kind %d", sample.Kind)
	}

	payloadLen := sample.PayloadLen
	if payloadLen > uint32(len(sample.Payload)) {
		payloadLen = uint32(len(sample.Payload))
	}
	payload := make([]byte, payloadLen)
	copy(payload, sample.Payload[:payloadLen])

	return dnsSample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:   sample.CgroupId,
		TsNs:       sample.TsNs,
		Source:     DNSSource(sample.Source),
		Family:     sample.Family,
		Dport:      sample.Dport,
		DaddrV4:    sample.DaddrV4,
		DaddrV6:    sample.DaddrV6,
		Payload:    payload,
		PayloadLen: uint32(len(payload)),
	}, nil
}
