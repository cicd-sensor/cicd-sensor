package kerneltracker

import (
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

// HTTPSource enumerates the kernel tap that produced an HTTP request sample.
// These numeric values are part of the ringbuf ABI and must stay in sync with
// HTTP_SOURCE_* in internal/agent/bpf.
type HTTPSource uint8

const (
	HTTPSourceCleartext HTTPSource = 0
	HTTPSourceOpenSSL   HTTPSource = 1
)

// httpRequestSample is the userspace mirror of struct http_request_sample.
// Fields arrive already parsed and query-stripped by the in-eBPF parse; the
// raw request bytes never cross the kernel boundary.
type httpRequestSample struct {
	Identity processIdentity
	CgroupID uint64
	TsNs     uint64
	Source   HTTPSource
	Method   string
	Path     string
	Host     string
}

func (httpRequestSample) sealedEngineInput()         {}
func (httpRequestSample) sealedDecodedKernelSample() {}

// handleHTTPRequestSample turns one httpRequestSample into at most one
// http_request EventRecord.
func handleHTTPRequestSample(state *jobTrackingState, sample httpRequestSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	source, ok := httpSourceValue(sample.Source)
	if !ok {
		return nil
	}
	// The kernel parse only submits samples with a matched method token and
	// an origin-form path; treat anything else as ABI skew and drop it.
	if sample.Method == "" || !strings.HasPrefix(sample.Path, "/") {
		return nil
	}

	// Every rule-facing string in this repo is lowercase, so the payload is
	// lowercased here too: what a job log shows is then exactly what a rule
	// matches on. Rules stay readable either way — CEL string literals go
	// through the same normalization (celengine.normalizeStringLiterals), so
	// `method == "POST"` and `method == "post"` both hit.
	record := jobevent.EventRecord{
		EventType: jobevent.HTTPRequest,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"method": strings.ToLower(sample.Method),
			"path":   strings.ToLower(sample.Path),
			"host":   normalizeHTTPHost(sample.Host),
			"source": source,
		},
		Tags: map[string]string{},
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}

// normalizeHTTPHost returns the rule-facing Host value. The kernel copies the
// value verbatim up to the header line's CR/LF, so trim leading/trailing OWS
// (RFC 9112 §5.1 excludes it; padding must not let an attacker dodge a
// `host == "..."` rule) and lowercase (host names are case-insensitive). A
// value with an embedded control byte is malformed — a parser differential
// that could read as a benign prefix to us but differently upstream — so it is
// simply dropped to an empty host, which matches no host rule.
func normalizeHTTPHost(raw string) string {
	host := strings.Trim(raw, " \t")
	if strings.IndexFunc(host, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return ""
	}
	return strings.ToLower(host)
}

// httpSourceValue maps the ABI source tag to the rule-facing source string.
// Unknown values mean kernel/userspace skew; the caller drops the sample.
func httpSourceValue(source HTTPSource) (string, bool) {
	switch source {
	case HTTPSourceCleartext:
		return "cleartext_http", true
	case HTTPSourceOpenSSL:
		return "openssl", true
	default:
		return "", false
	}
}
