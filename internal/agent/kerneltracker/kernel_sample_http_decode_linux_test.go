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

func TestDecodeHTTPRequestSample(t *testing.T) {
	t.Parallel()

	setCChars := func(dst []int8, value string) {
		for i, b := range []byte(value) {
			dst[i] = int8(b)
		}
	}

	// host is the raw Host bytes written into the fixed-size array; a NUL
	// inside it exercises the C-string decode boundary.
	buildSample := func(t *testing.T, kind uint32, host string) []byte {
		t.Helper()

		sample := bpfprog.BPFProgramHttpRequestSample{
			Kind:          kind,
			Source:        0,
			TsNs:          701,
			CgroupId:      801,
			StartBoottime: 901,
			Tgid:          1001,
		}
		setCChars(sample.Method[:], "POST")
		setCChars(sample.Path[:], "/api/upload")
		setCChars(sample.Host[:], host)

		var buffer bytes.Buffer
		if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
			t.Fatalf("binary.Write() error = %v", err)
		}
		return buffer.Bytes()
	}

	tests := []struct {
		name       string
		sample     []byte
		want       httpRequestSample
		wantErrSub string
	}{
		{
			name:   "valid",
			sample: buildSample(t, kernelio.SampleKindHTTPRequest, "api.example.com"),
			want: httpRequestSample{
				Identity: processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID: 801,
				TsNs:     701,
				Source:   HTTPSourceCleartext,
				Method:   "POST",
				Path:     "/api/upload",
				Host:     "api.example.com",
			},
		},
		{
			// Host is a fixed-size char array decoded as a C string, so an
			// embedded NUL terminates the value: the suffix is lost (truncation,
			// not rejection). NUL is a malformed field value (RFC 9110); this is
			// accepted best-effort behavior and normalizeHTTPHost never sees it.
			name:   "embedded_nul_truncates_host",
			sample: buildSample(t, kernelio.SampleKindHTTPRequest, "a.example\x00.evil.example"),
			want: httpRequestSample{
				Identity: processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID: 801,
				TsNs:     701,
				Source:   HTTPSourceCleartext,
				Method:   "POST",
				Path:     "/api/upload",
				Host:     "a.example",
			},
		},
		{
			name:       "unexpected_size",
			sample:     buildSample(t, kernelio.SampleKindHTTPRequest, "api.example.com")[:binary.Size(bpfprog.BPFProgramHttpRequestSample{})-1],
			wantErrSub: "unexpected http request sample size",
		},
		{
			name:       "unexpected_kind",
			sample:     buildSample(t, 99, "api.example.com"),
			wantErrSub: "unexpected http request sample kind",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeHTTPRequestSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeHTTPRequestSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeHTTPRequestSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeHTTPRequestSample() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("decodeHTTPRequestSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}
