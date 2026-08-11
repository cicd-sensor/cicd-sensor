//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"fmt"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// decodeHTTPRequestSample decodes the already-parsed method/path/host fields.
// The kernel-side parse guarantees the sample never carries raw request
// bytes, so decoding is plain NUL-terminated string extraction.
func decodeHTTPRequestSample(raw []byte) (httpRequestSample, error) {
	if len(raw) != binary.Size(bpfprog.BPFProgramHttpRequestSample{}) {
		return httpRequestSample{}, fmt.Errorf("unexpected http request sample size %d", len(raw))
	}

	var sample bpfprog.BPFProgramHttpRequestSample
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &sample); err != nil {
		return httpRequestSample{}, fmt.Errorf("read http request sample: %w", err)
	}
	if sample.Kind != kernelio.SampleKindHTTPRequest {
		return httpRequestSample{}, fmt.Errorf("unexpected http request sample kind %d", sample.Kind)
	}

	return httpRequestSample{
		Identity: processIdentity{
			PID:           sample.Tgid,
			StartBoottime: sample.StartBoottime,
		},
		CgroupID: sample.CgroupId,
		TsNs:     sample.TsNs,
		Source:   HTTPSource(sample.Source),
		Method:   cString(sample.Method[:]),
		Path:     cString(sample.Path[:]),
		Host:     cString(sample.Host[:]),
	}, nil
}
