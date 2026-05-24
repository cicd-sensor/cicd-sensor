package kerneltracker

import (
	"net"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

type netConnectV4Sample struct {
	Identity   processIdentity
	CgroupID   uint64
	RemoteIPv4 [4]byte
	Port       uint16
	Protocol   uint8
	TsNs       uint64
	Blocked    bool
}

func (netConnectV4Sample) sealedEngineInput()         {}
func (netConnectV4Sample) sealedDecodedKernelSample() {}

type netConnectV6Sample struct {
	Identity   processIdentity
	CgroupID   uint64
	RemoteIPv6 [16]byte
	Port       uint16
	Protocol   uint8
	TsNs       uint64
	Blocked    bool
}

func (netConnectV6Sample) sealedEngineInput()         {}
func (netConnectV6Sample) sealedDecodedKernelSample() {}

func handleNetConnectV4Sample(state *jobTrackingState, sample netConnectV4Sample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}
	if sample.Port == 0 {
		return nil
	}

	record := jobevent.EventRecord{
		EventType: jobevent.NetworkConnect,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"remote_ip":   net.IP(sample.RemoteIPv4[:]).String(),
			"remote_port": int(sample.Port),
			"protocol":    protocolName(sample.Protocol),
			"family":      "ipv4",
		},
		Tags: map[string]string{},
	}
	if sample.Blocked {
		record.Tags["block_source"] = "kernel"
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}

func handleNetConnectV6Sample(state *jobTrackingState, sample netConnectV6Sample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}
	if sample.Port == 0 {
		return nil
	}

	remoteIP, family := remoteIPAndFamily(sample.RemoteIPv6[:])
	record := jobevent.EventRecord{
		EventType: jobevent.NetworkConnect,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"remote_ip":   remoteIP,
			"remote_port": int(sample.Port),
			"protocol":    protocolName(sample.Protocol),
			"family":      family,
		},
		Tags: map[string]string{},
	}
	if sample.Blocked {
		record.Tags["block_source"] = "kernel"
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}

func remoteIPAndFamily(raw []byte) (string, string) {
	ip := net.IP(raw)
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), "ipv4"
	}
	return ip.String(), "ipv6"
}

func protocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "unknown"
	}
}
