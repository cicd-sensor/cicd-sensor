package kerneltracker

import (
	"path"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

// unixSocketConnectSample mirrors unix_socket_connect_sample. The handler renders
// SunPath/Cwd into the rule-facing path.
type unixSocketConnectSample struct {
	Identity         processIdentity
	CgroupID         uint64
	TsNs             uint64
	SunPath          []byte
	SunPathLen       uint32
	SunPathTruncated bool
	Cwd              string
	CwdTruncated     bool
	CwdUnavailable   bool
	SocketType       uint8
	IsAbstract       bool
}

func (unixSocketConnectSample) sealedEngineInput()         {}
func (unixSocketConnectSample) sealedDecodedKernelSample() {}

const (
	sockTypeStream    uint8 = 1
	sockTypeDgram     uint8 = 2
	sockTypeSeqPacket uint8 = 5
)

func socketTypeName(socketType uint8) string {
	switch socketType {
	case sockTypeStream:
		return "stream"
	case sockTypeDgram:
		return "dgram"
	case sockTypeSeqPacket:
		return "seqpacket"
	default:
		return "unknown"
	}
}

// renderUnixPath normalizes the three sockaddr_un forms into the rule-facing
// path: filesystem paths stay absolute, Linux abstract sockets stay "@name",
// and relative paths are resolved from the sampled cwd when available.
func renderUnixPath(sample unixSocketConnectSample) string {
	tail := trimSunPath(sample.SunPath, sample.IsAbstract)
	if sample.IsAbstract {
		return tail
	}
	if tail == "" {
		return ""
	}
	if tail[0] == '/' {
		return tail
	}
	if sample.Cwd == "" || sample.CwdUnavailable {
		return tail
	}
	return path.Clean(sample.Cwd + "/" + tail)
}

// trimSunPath applies sockaddr_un.sun_path termination rules.
//
// Filesystem/relative sockets are NUL-terminated strings. Linux abstract
// sockets start with NUL and use the following bytes as the namespace name, so
// we render them with "@" to make the leading NUL visible to rules and logs.
func trimSunPath(raw []byte, isAbstract bool) string {
	if isAbstract {
		if len(raw) == 0 || raw[0] != 0 {
			return "@"
		}
		end := 1
		for end < len(raw) && raw[end] != 0 {
			end++
		}
		return "@" + string(raw[1:end])
	}
	end := 0
	for end < len(raw) && raw[end] != 0 {
		end++
	}
	return string(raw[:end])
}

func handleUnixSocketConnectSample(state *jobTrackingState, sample unixSocketConnectSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	record := jobevent.EventRecord{
		EventType: jobevent.UnixSocketConnect,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"path":        renderUnixPath(sample),
			"socket_type": socketTypeName(sample.SocketType),
			"is_abstract": sample.IsAbstract,
		},
		Tags: map[string]string{},
	}
	if sample.SunPathTruncated || sample.CwdTruncated {
		record.Tags["truncated"] = "path"
	}
	if sample.CwdUnavailable {
		record.Tags["cwd_unavailable"] = "true"
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}
