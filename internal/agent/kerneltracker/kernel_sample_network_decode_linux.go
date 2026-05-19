//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func decodeNetConnectV4Sample(raw []byte) (netConnectV4Sample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramNetV4Sample{}) {
		return netConnectV4Sample{}, fmt.Errorf("unexpected net connect v4 sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramNetV4Sample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return netConnectV4Sample{}, fmt.Errorf("read net connect v4 sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindNetworkConnectV4 {
		return netConnectV4Sample{}, fmt.Errorf("unexpected net connect v4 sample kind %d", sample.Kind)
	}

	var remoteIP [4]byte
	for index := range remoteIP {
		remoteIP[index] = sample.RemoteIp[index]
	}

	return netConnectV4Sample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:   sample.CgroupId,
		RemoteIPv4: remoteIP,
		Port:       sample.RemotePort,
		Protocol:   sample.Protocol,
		TsNs:       sample.TsNs,
		Blocked:    sample.Blocked != 0,
	}, nil
}

func decodeNetConnectV6Sample(raw []byte) (netConnectV6Sample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramNetV6Sample{}) {
		return netConnectV6Sample{}, fmt.Errorf("unexpected net connect v6 sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramNetV6Sample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return netConnectV6Sample{}, fmt.Errorf("read net connect v6 sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindNetworkConnectV6 {
		return netConnectV6Sample{}, fmt.Errorf("unexpected net connect v6 sample kind %d", sample.Kind)
	}

	var remoteIP [16]byte
	for index := range remoteIP {
		remoteIP[index] = sample.RemoteIp[index]
	}

	return netConnectV6Sample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:   sample.CgroupId,
		RemoteIPv6: remoteIP,
		Port:       sample.RemotePort,
		Protocol:   sample.Protocol,
		TsNs:       sample.TsNs,
		Blocked:    sample.Blocked != 0,
	}, nil
}
