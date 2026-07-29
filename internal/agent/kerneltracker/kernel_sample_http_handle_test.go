package kerneltracker

import (
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

// TestNormalizeHTTPHost pins the rule-facing Host normalization directly. The
// kernel copies the Host value verbatim up to the header CR/LF; this is the one
// place OWS trimming, lowercasing, and the control-byte drop happen, so an
// attacker cannot pad or splice a value to dodge a `host == "..."` rule.
func TestNormalizeHTTPHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "plain value passes through", raw: "example.com", want: "example.com"},
		{name: "mixed case lowercased", raw: "API.Example.COM", want: "api.example.com"},
		{name: "port is kept", raw: "example.com:8080", want: "example.com:8080"},
		{name: "leading OWS (spaces and tab) trimmed", raw: "  \texample.com", want: "example.com"},
		{
			name: "many leading spaces cannot survive to dodge host==",
			raw:  strings.Repeat(" ", 9) + "evil.example",
			want: "evil.example",
		},
		{name: "trailing OWS trimmed", raw: "evil.example   ", want: "evil.example"},
		{name: "OWS on both sides trimmed then lowercased", raw: "  API.example.com  ", want: "api.example.com"},
		{
			// A parser differential: the NUL could read as a benign prefix to us
			// but split differently upstream, so the whole value is dropped.
			name: "embedded NUL drops the value to empty",
			raw:  "safe.example\x00evil.example",
			want: "",
		},
		{name: "embedded control byte drops the value to empty", raw: "exam\x01ple.com", want: ""},
		{name: "empty stays empty", raw: "", want: ""},
		{name: "only OWS trims to empty", raw: "  \t ", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeHTTPHost(tt.raw); got != tt.want {
				t.Fatalf("normalizeHTTPHost(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestHandleHTTPRequest_EmitsEvent(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/usr/bin/curl", nil, 0)

	effects := handleEngineInput(state, httpRequestSample{
		Identity: identity,
		CgroupID: 42,
		TsNs:     17,
		Source:   HTTPSourceCleartext,
		Method:   "POST",
		Path:     "/api/upload",
		// Mixed case: Host header names a case-insensitive DNS name and
		// must be lowercased like domain events.
		Host: "API.Example.COM",
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if emit.Record.EventType != jobevent.HTTPRequest {
		t.Fatalf("kind = %q, want %q", emit.Record.EventType, jobevent.HTTPRequest)
	}
	wantPayload := map[string]any{
		"method": "POST",
		"path":   "/api/upload",
		"host":   "api.example.com",
		"source": "cleartext_http",
	}
	for key, want := range wantPayload {
		if got := emit.Record.Payload[key]; got != want {
			t.Fatalf("payload[%s] = %#v, want %#v", key, got, want)
		}
	}
	if len(emit.Record.Payload) != len(wantPayload) {
		t.Fatalf("payload keys = %d, want %d (%#v)", len(emit.Record.Payload), len(wantPayload), emit.Record.Payload)
	}
}

func TestHandleHTTPRequest_NormalizesHost(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/usr/bin/curl", nil, 0)

	// The kernel copies the Host verbatim (OWS, mixed case); userspace trims
	// and lowercases so padding cannot dodge a host rule.
	effects := handleEngineInput(state, httpRequestSample{
		Identity: identity,
		CgroupID: 42,
		Source:   HTTPSourceCleartext,
		Method:   "GET",
		Path:     "/",
		Host:     "   API.Example.COM  ",
	})

	emit, ok := singleEmitEventRecordEffect(effects)
	if !ok {
		t.Fatalf("effects = %#v, want single emitEventRecord", effects)
	}
	if got := emit.Record.Payload["host"]; got != "api.example.com" {
		t.Fatalf("payload[host] = %#v, want \"api.example.com\"", got)
	}
}

func TestHandleHTTPRequest_UntrackedCgroupDropped(t *testing.T) {
	t.Parallel()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	identity := processIdentity{PID: 101, StartBoottime: 2}

	state := destinationTrackedState(jobID, 42)
	state.recordExec(jobID, identity, "/usr/bin/curl", nil, 0)

	// cgroup 43 is not tracked: the sample must not attribute to any job.
	effects := handleEngineInput(state, httpRequestSample{
		Identity: identity,
		CgroupID: 43,
		Source:   HTTPSourceCleartext,
		Method:   "GET",
		Path:     "/",
	})

	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none", effects)
	}
}

func TestHandleHTTPRequest_DropsMalformedSamples(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		sample httpRequestSample
	}{
		{
			// The kernel parse never submits an empty method; reaching here
			// means kernel/userspace ABI skew, and a half-formed event must
			// not be emitted.
			name: "empty method rejected",
			sample: httpRequestSample{
				Source: HTTPSourceCleartext,
				Path:   "/",
			},
		},
		{
			// Origin-form is guaranteed in-kernel; a non-'/' path is skew.
			name: "non-origin-form path rejected",
			sample: httpRequestSample{
				Source: HTTPSourceCleartext,
				Method: "GET",
				Path:   "example.com:443",
			},
		},
		{
			// A source value this userspace build does not know cannot be
			// mapped to a rule-facing source string — drop, don't guess.
			name: "unknown source rejected",
			sample: httpRequestSample{
				Source: HTTPSource(200),
				Method: "GET",
				Path:   "/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
			identity := processIdentity{PID: 101, StartBoottime: 2}

			state := destinationTrackedState(jobID, 42)
			state.recordExec(jobID, identity, "/usr/bin/curl", nil, 0)

			sample := tt.sample
			sample.Identity = identity
			sample.CgroupID = 42

			if effects := handleEngineInput(state, sample); len(effects) != 0 {
				t.Fatalf("effects = %#v, want none", effects)
			}
		})
	}
}
