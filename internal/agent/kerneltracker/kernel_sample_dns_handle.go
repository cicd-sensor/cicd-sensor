package kerneltracker

import (
	"bytes"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"golang.org/x/net/dns/dnsmessage"
)

// DNSSource enumerates the kernel hook channel that produced a DNS sample.
// These numeric values are part of the ringbuf ABI and must stay in sync with
// DNS_SOURCE_* in internal/agent/bpf.
type DNSSource uint8

const (
	DNSSourceUDP             DNSSource = 0
	DNSSourceTCP             DNSSource = 1
	DNSSourceSystemdResolved DNSSource = 2
)

// dnsSample is the userspace mirror of struct dns_sample. Payload is already
// trimmed to the meaningful payload length by the kernel sample parser.
type dnsSample struct {
	Identity   processIdentity
	CgroupID   uint64
	TsNs       uint64
	Source     DNSSource
	Family     uint8
	Dport      uint16
	DaddrV4    [4]byte
	DaddrV6    [16]byte
	Payload    []byte
	PayloadLen uint32
}

func (dnsSample) sealedEngineInput()         {}
func (dnsSample) sealedDecodedKernelSample() {}

// handleDNSSample turns one dnsSample into at most one domain EventRecord.
func handleDNSSample(state *jobTrackingState, sample dnsSample) []engineEffect {
	jobID, ok := state.jobForCgroup(sample.CgroupID)
	if !ok {
		return nil
	}

	var domain string
	switch sample.Source {
	case DNSSourceSystemdResolved:
		domain, ok = parseSystemdResolvedQuery(sample.Payload)
	case DNSSourceTCP:
		if len(sample.Payload) < 2 {
			return nil
		}
		domain, ok = parseDNSQuery(sample.Payload[2:])
	default:
		domain, ok = parseDNSQuery(sample.Payload)
	}
	if !ok || isLocalNameResolution(domain) {
		return nil
	}

	record := jobevent.EventRecord{
		EventType: jobevent.Domain,
		Timestamp: bootNsToUTC(sample.TsNs),
		Process:   state.lookupProcessSummary(jobID, sample.Identity),
		Payload: map[string]any{
			"domain": domain,
			// All DNS observation paths share the rule-facing source value.
			"source": "dns",
		},
		Tags: map[string]string{},
	}
	return []engineEffect{emitEventRecord{JobID: jobID, Record: record}}
}

func parseDNSQuery(payload []byte) (string, bool) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(payload); err != nil {
		return "", false
	}

	question, err := parser.Question()
	if err != nil {
		return "", false
	}

	name := strings.ToLower(question.Name.String())
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", false
	}
	return name, true
}

// parseSystemdResolvedQuery extracts the queried hostname from a Varlink message.
func parseSystemdResolvedQuery(payload []byte) (string, bool) {
	if i := bytes.IndexByte(payload, 0); i >= 0 {
		payload = payload[:i]
	}
	if len(payload) == 0 {
		return "", false
	}

	if !bytes.Contains(payload, []byte("io.systemd.Resolve.ResolveHostname")) &&
		!bytes.Contains(payload, []byte("io.systemd.Resolve.ResolveRecord")) {
		return "", false
	}

	rest := payload
	if i := bytes.Index(rest, []byte(`"name"`)); i >= 0 {
		rest = rest[i+len(`"name"`):]
	} else {
		return "", false
	}
	if i := bytes.IndexByte(rest, ':'); i >= 0 {
		rest = rest[i+1:]
	} else {
		return "", false
	}
	if i := bytes.IndexByte(rest, '"'); i >= 0 {
		rest = rest[i+1:]
	} else {
		return "", false
	}
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return "", false
	}
	name := strings.TrimSuffix(strings.ToLower(string(rest[:end])), ".")
	if name == "" {
		return "", false
	}
	return name, true
}

var rfc6761SpecialUseTLDs = []string{".example", ".invalid", ".localhost", ".test"}

func isLocalNameResolution(domain string) bool {
	name := strings.TrimSuffix(strings.ToLower(domain), ".")
	if name == "" {
		return true
	}
	if !strings.Contains(name, ".") {
		return true
	}
	for _, suffix := range rfc6761SpecialUseTLDs {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
