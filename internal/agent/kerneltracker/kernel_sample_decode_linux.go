//go:build linux

package kerneltracker

import (
	"encoding/binary"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// decodeKernelSample dispatches one raw ringbuf sample to the matching decoder.
func decodeKernelSample(sample kernelio.KernelSample) (decodedKernelSample, error) {
	if len(sample) < 4 {
		return nil, fmt.Errorf("sample too short: %d", len(sample))
	}

	kind := binary.LittleEndian.Uint32(sample[:4])
	raw := []byte(sample)
	switch kind {
	case kernelio.SampleKindFork:
		return decodeForkSample(raw)
	case kernelio.SampleKindCgroupMkdir:
		return decodeCgroupMkdirSample(raw)
	case kernelio.SampleKindCgroupAttach:
		return decodeCgroupAttachSample(raw)
	case kernelio.SampleKindCgroupRmdir:
		return decodeCgroupRmdirSample(raw)
	case kernelio.SampleKindExec:
		return decodeExecSample(raw)
	case kernelio.SampleKindNetworkConnectV4:
		return decodeNetConnectV4Sample(raw)
	case kernelio.SampleKindNetworkConnectV6:
		return decodeNetConnectV6Sample(raw)
	case kernelio.SampleKindFileOpen:
		return decodeFileOpenSample(raw)
	case kernelio.SampleKindFileRemove:
		return decodeFileRemoveSample(raw)
	case kernelio.SampleKindFileMove:
		return decodeFileMoveSample(raw)
	case kernelio.SampleKindFileLink:
		return decodeFileLinkSample(raw)
	case kernelio.SampleKindDNS:
		return decodeDNSSample(raw)
	case kernelio.SampleKindUnixSocketConnect:
		return decodeUnixSocketConnectSample(raw)
	default:
		return nil, fmt.Errorf("unknown sample kind %d", kind)
	}
}

func cString(data []int8) string {
	length := 0
	for length < len(data) && data[length] != 0 {
		length++
	}

	bytes := make([]byte, length)
	for index := 0; index < length; index++ {
		bytes[index] = byte(data[index])
	}

	return string(bytes)
}

func cBytes(data []int8, length uint32) ([]byte, error) {
	if length > uint32(len(data)) {
		return nil, fmt.Errorf("length %d exceeds C char buffer size %d", length, len(data))
	}

	bytes := make([]byte, int(length))
	for index := range bytes {
		bytes[index] = byte(data[index])
	}

	return bytes, nil
}

// pathFromBuffer reads a string from a kernel path buffer with a dentry offset.
func pathFromBuffer(buf []int8, offset uint16) string {
	if int(offset) >= len(buf) {
		return ""
	}
	return cString(buf[offset:])
}
