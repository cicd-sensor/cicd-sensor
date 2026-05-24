package kerneltracker

import (
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

func TestDecodeDNSQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		payload    []byte
		wantDomain string
		wantOK     bool
	}{
		{
			name:       "ipv4_a_query",
			payload:    buildDNSQuery(t, "example.com", dnsmessage.TypeA),
			wantDomain: "example.com",
			wantOK:     true,
		},
		{
			name:       "ipv6_aaaa_query",
			payload:    buildDNSQuery(t, "ipv6.example.com", dnsmessage.TypeAAAA),
			wantDomain: "ipv6.example.com",
			wantOK:     true,
		},
		{
			name:       "lowercases_mixed_case",
			payload:    buildDNSQuery(t, "Registry.NPMJS.org", dnsmessage.TypeA),
			wantDomain: "registry.npmjs.org",
			wantOK:     true,
		},
		{
			name:       "trailing_dot_stripped",
			payload:    buildDNSQuery(t, "example.com.", dnsmessage.TypeA),
			wantDomain: "example.com",
			wantOK:     true,
		},
		{
			name:       "empty_payload_rejected",
			payload:    nil,
			wantDomain: "",
			wantOK:     false,
		},
		{
			name:       "truncated_header_rejected",
			payload:    []byte{0x12, 0x34, 0x01},
			wantDomain: "",
			wantOK:     false,
		},
		{
			name:       "garbage_after_header_rejected",
			payload:    truncateAfterHeader(t, buildDNSQuery(t, "example.com", dnsmessage.TypeA)),
			wantDomain: "",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := parseDNSQuery(tt.payload)
			if ok != tt.wantOK {
				t.Fatalf("ok: got %v, want %v", ok, tt.wantOK)
			}
			if got != tt.wantDomain {
				t.Fatalf("domain: got %q, want %q", got, tt.wantDomain)
			}
		})
	}
}

func buildDNSQuery(t *testing.T, name string, kind dnsmessage.Type) []byte {
	t.Helper()

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(canonicalize(name)),
			Type:  kind,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack DNS query: %v", err)
	}
	return packed
}

// truncateAfterHeader returns the first 12 bytes (header only) of a DNS
// query, simulating a packet whose Question section was clipped off.
func truncateAfterHeader(t *testing.T, full []byte) []byte {
	t.Helper()
	if len(full) < 12 {
		t.Fatalf("packet shorter than DNS header (%d bytes)", len(full))
	}
	return append([]byte(nil), full[:12]...)
}

// canonicalize ensures the name ends with the trailing dot dnsmessage
// requires, regardless of how the caller wrote it.
func canonicalize(name string) string {
	if len(name) == 0 || name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}

func TestDecodeSystemdResolvedQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		want    string
		wantOK  bool
	}{
		{
			name:    "ResolveHostname extracts name",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"example.com","family":0,"flags":0}}` + "\x00",
			want:    "example.com",
			wantOK:  true,
		},
		{
			name:    "uppercase hostname is lowercased",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"EXAMPLE.com"}}` + "\x00",
			want:    "example.com",
			wantOK:  true,
		},
		{
			name:    "trailing dot is stripped",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"example.com."}}` + "\x00",
			want:    "example.com",
			wantOK:  true,
		},
		{
			name:    "no NUL terminator still parses",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"a.example.com"}}`,
			want:    "a.example.com",
			wantOK:  true,
		},
		{
			name:    "ResolveAddress is dropped",
			payload: `{"method":"io.systemd.Resolve.ResolveAddress","parameters":{"address":[1,2,3,4]}}` + "\x00",
			wantOK:  false,
		},
		{
			name:    "missing parameters.name returns false",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"family":0}}` + "\x00",
			wantOK:  false,
		},
		{
			name:    "empty name returns false",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":""}}` + "\x00",
			wantOK:  false,
		},
		{
			name:    "garbage bytes return false",
			payload: "\x01\x02\x03not json\x00",
			wantOK:  false,
		},
		{
			name:    "empty payload returns false",
			payload: "",
			wantOK:  false,
		},
		{
			name:    "NUL-only payload returns false",
			payload: "\x00",
			wantOK:  false,
		},
		{
			name:    "name with mixed case and trailing dot",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"Mixed.Case.example.com."}}` + "\x00",
			want:    "mixed.case.example.com",
			wantOK:  true,
		},
		{
			name:    "long name fits in buffer",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"` + strings.Repeat("a", 200) + `.com"}}` + "\x00",
			want:    strings.Repeat("a", 200) + ".com",
			wantOK:  true,
		},
		{
			// Kernel buffer clipped mid-message (no closing brace, no
			// NUL) — strict json.Unmarshal would drop this, byte-scan
			// extracts the visible name.
			name:    "truncated after name still extracts",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"truncated.example.com","fa`,
			want:    "truncated.example.com",
			wantOK:  true,
		},
		{
			// Closing quote missing because the buffer cap landed
			// inside the hostname value.
			name:    "name unterminated at buffer boundary returns false",
			payload: `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"verylongname.example.com.no-closing`,
			wantOK:  false,
		},
		{
			// Field order swap: parameters first, method later.
			name:    "method-after-parameters still parses",
			payload: `{"parameters":{"name":"reordered.example.com"},"method":"io.systemd.Resolve.ResolveHostname"}` + "\x00",
			want:    "reordered.example.com",
			wantOK:  true,
		},
		{
			// Whitespace around the method's colon — pretty-printed
			// Varlink. Bare-substring method matcher accepts it.
			name:    "whitespace around method colon still parses",
			payload: `{"method" : "io.systemd.Resolve.ResolveHostname", "parameters":{"name":"spaced.example.com"}}` + "\x00",
			want:    "spaced.example.com",
			wantOK:  true,
		},
		{
			// Whitespace inside the "name" pair as well — fully
			// pretty-printed JSON.
			name:    "whitespace inside name pair still parses",
			payload: "{\n  \"method\" : \"io.systemd.Resolve.ResolveHostname\",\n  \"parameters\" : {\n    \"name\" : \"pretty.example.com\"\n  }\n}\x00",
			want:    "pretty.example.com",
			wantOK:  true,
		},
		{
			// ResolveRecord is the generic-record lookup path (dig and
			// similar). parameters.name is the queried zone.
			name:    "ResolveRecord extracts name",
			payload: `{"method":"io.systemd.Resolve.ResolveRecord","parameters":{"name":"record.example.com","class":1,"type":28}}` + "\x00",
			want:    "record.example.com",
			wantOK:  true,
		},
		{
			// ResolveService also has a `name` field but it is the
			// service instance, not the queried zone. Drop.
			name:    "ResolveService is dropped",
			payload: `{"method":"io.systemd.Resolve.ResolveService","parameters":{"name":"_http._tcp","type":"_http._tcp","domain":"example.com"}}` + "\x00",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseSystemdResolvedQuery([]byte(tt.payload))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Fatalf("name = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsLocalNameResolution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{name: "single label hostname", domain: "ubuntu-2204", want: true},
		{name: "single label localhost", domain: "localhost", want: true},
		{name: "single label test", domain: "test", want: true},
		{name: "rfc6761 example tld", domain: "foo.example", want: true},
		{name: "rfc6761 invalid tld", domain: "anything.invalid", want: true},
		{name: "rfc6761 localhost tld", domain: "x.localhost", want: true},
		{name: "rfc6761 test tld", domain: "ci.svc.test", want: true},
		{name: "trailing dot single label", domain: "host.", want: true},
		{name: "uppercase rfc6761", domain: "FOO.LOCALHOST", want: true},
		{name: "empty string", domain: "", want: true},
		{name: "multi label public", domain: "registry.npmjs.org", want: false},
		{name: "mdns local not filtered", domain: "printer.local", want: false},
		{name: "reverse v4 zone not filtered", domain: "1.0.0.127.in-addr.arpa", want: false},
		{name: "example as second-level not filtered", domain: "example.com", want: false},
		{name: "invalid as label substring not filtered", domain: "invalid.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isLocalNameResolution(tt.domain); got != tt.want {
				t.Fatalf("isLocalNameResolution(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestHandleDNS_EmitsDomainEvent(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/usr/bin/curl", nil, 0)

	effects := handleEngineInput(state, dnsSample{
		Identity: identity,
		CgroupID: 42,
		TsNs:     17,
		Source:   DNSSourceUDP,
		Family:   2,
		Dport:    53,
		Payload:  buildDNSQuery(t, "registry.npmjs.org", dnsmessage.TypeA),
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if emit.Record.EventType != jobevent.Domain {
		t.Fatalf("kind = %q, want %q", emit.Record.EventType, jobevent.Domain)
	}
	if got, _ := emit.Record.Payload["domain"].(string); got != "registry.npmjs.org" {
		t.Fatalf("payload[domain] = %q, want registry.npmjs.org", got)
	}
	if got, _ := emit.Record.Payload["source"].(string); got != "dns" {
		t.Fatalf("payload[source] = %q, want dns", got)
	}
}

func TestHandleDNS_DropsUnparseablePayload(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "", nil, 0)

	// Truncated DNS header (3 bytes instead of 12) should be dropped
	// silently — handleDNSSample must return no effects rather than emit a
	// half-formed event with empty domain.
	effects := handleEngineInput(state, dnsSample{
		Identity: identity,
		CgroupID: 42,
		Source:   DNSSourceUDP,
		Payload:  []byte{0x12, 0x34, 0x01},
	})

	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none", effects)
	}
}

func TestHandleDNS_TCPSkipsLengthPrefix(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/usr/bin/curl", nil, 0)

	// RFC 1035 §4.2.2: TCP DNS prepends a 2-byte BE length to the message.
	// The kernel hook captures the raw bytes including the prefix; userspace
	// must strip it before parsing.
	body := buildDNSQuery(t, "evil.example.com", dnsmessage.TypeA)
	tcpPayload := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(tcpPayload[:2], uint16(len(body)))
	copy(tcpPayload[2:], body)

	effects := handleEngineInput(state, dnsSample{
		Identity: identity,
		CgroupID: 42,
		TsNs:     17,
		Source:   DNSSourceTCP,
		Family:   2,
		Dport:    53,
		Payload:  tcpPayload,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if got, _ := emit.Record.Payload["domain"].(string); got != "evil.example.com" {
		t.Fatalf("payload[domain] = %q, want evil.example.com", got)
	}
	if got, _ := emit.Record.Payload["source"].(string); got != "dns" {
		t.Fatalf("payload[source] = %q, want dns", got)
	}
}

func TestHandleDNS_SystemdResolvedEmitsDomainEvent(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/usr/bin/curl", nil, 0)

	// systemd-resolved Varlink line protocol: NUL-terminated JSON.
	payload := []byte(`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"resolve.example.com","family":0}}` + "\x00")

	effects := handleEngineInput(state, dnsSample{
		Identity: identity,
		CgroupID: 42,
		TsNs:     17,
		Source:   DNSSourceSystemdResolved,
		Payload:  payload,
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if got, _ := emit.Record.Payload["domain"].(string); got != "resolve.example.com" {
		t.Fatalf("payload[domain] = %q, want resolve.example.com", got)
	}
	if got, _ := emit.Record.Payload["source"].(string); got != "dns" {
		t.Fatalf("payload[source] = %q, want dns", got)
	}
}

func TestHandleDNS_SystemdResolvedDropsResolveAddress(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "", nil, 0)

	// ResolveAddress is the reverse-lookup variant (IP -> name) and does
	// not carry a queried hostname. handleDNSSample must drop it silently —
	// systemd-resolved sends ResolveAddress, ResolveRecord, etc. on the
	// same socket as ResolveHostname, so the kernel hook fires for all
	// of them.
	payload := []byte(`{"method":"io.systemd.Resolve.ResolveAddress","parameters":{"address":[1,2,3,4]}}` + "\x00")

	effects := handleEngineInput(state, dnsSample{
		Identity: identity,
		CgroupID: 42,
		Source:   DNSSourceSystemdResolved,
		Payload:  payload,
	})

	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none", effects)
	}
}

func TestHandleDNS_TCPDropsTooShortForPrefix(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "", nil, 0)

	// 1 byte cannot contain the 2-byte length prefix; handleDNSSample must drop
	// silently rather than panic on the slice index.
	effects := handleEngineInput(state, dnsSample{
		Identity: identity,
		CgroupID: 42,
		Source:   DNSSourceTCP,
		Payload:  []byte{0x00},
	})

	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none", effects)
	}
}

// Local-name-resolution noise (single-label hostname queries from
// glibc / sudo / nss self-lookups, RFC 6761 placeholder TLDs) must be
// dropped before reaching the summary log so that domain rules and the
// HTML report do not surface intrinsically local traffic. The unit test
// of isLocalNameResolution pins the rule; this case pins the wiring at
// handleDNSSample.
func TestHandleDNS_DropsLocalNameResolution(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "", nil, 0)

	effects := handleEngineInput(state, dnsSample{
		Identity: identity,
		CgroupID: 42,
		TsNs:     17,
		Source:   DNSSourceUDP,
		Family:   2,
		Dport:    53,
		Payload:  buildDNSQuery(t, "ubuntu-2204", dnsmessage.TypeA),
	})

	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none", effects)
	}
}
