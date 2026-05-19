//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// decodeUnixSocketConnectSample trims sockaddr_un.sun_path and current cwd buffers.
func decodeUnixSocketConnectSample(raw []byte) (unixSocketConnectSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramUnixSocketConnectSample{}) {
		return unixSocketConnectSample{}, fmt.Errorf("unexpected unix socket connect sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramUnixSocketConnectSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return unixSocketConnectSample{}, fmt.Errorf("read unix socket connect sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindUnixSocketConnect {
		return unixSocketConnectSample{}, fmt.Errorf("unexpected unix socket connect sample kind %d", sample.Kind)
	}

	if sample.SunPathLen > uint32(len(sample.SunPath)) {
		return unixSocketConnectSample{}, fmt.Errorf("unix socket sun_path_len %d exceeds buffer size %d",
			sample.SunPathLen, len(sample.SunPath))
	}
	sunPath := make([]byte, sample.SunPathLen)
	copy(sunPath, sample.SunPath[:sample.SunPathLen])

	return unixSocketConnectSample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID:         sample.CgroupId,
		TsNs:             sample.TsNs,
		SunPath:          sunPath,
		SunPathLen:       sample.SunPathLen,
		SunPathTruncated: sample.SunPathTruncated != 0,
		Cwd:              pathFromBuffer(sample.Cwd[:], sample.CwdOffset),
		CwdTruncated:     sample.CwdTruncated != 0,
		CwdUnavailable:   sample.CwdUnavailable != 0,
		SocketType:       sample.SocketType,
		IsAbstract:       sample.IsAbstract != 0,
	}, nil
}
