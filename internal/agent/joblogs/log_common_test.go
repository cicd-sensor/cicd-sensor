package joblogs

import (
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func assertProtoEventProcessSanitized(t *testing.T, event *logv1.EventRecord) {
	t.Helper()
	if event == nil || event.GetProcess() == nil {
		t.Fatalf("event process missing: %#v", event)
	}
	if got, want := event.GetProcess().GetArgv()[1], "<redacted>"; got != want {
		t.Fatalf("event argv: got %q, want %q", got, want)
	}
	if got, want := event.GetProcess().GetAncestors()[0].GetArgv()[2], "<redacted>"; got != want {
		t.Fatalf("event ancestor argv: got %q, want %q", got, want)
	}
}

func eventWithSecretArgv() jobevent.EventRecord {
	return jobevent.EventRecord{
		ID:        "event-1",
		EventType: jobevent.ProcessExec,
		Timestamp: testLogTime(),
		Process: jobevent.ProcessSummary{
			PID:      100,
			ExecPath: "/usr/bin/curl",
			Argv:     []string{"curl", "--token=supersecret"},
			Ancestors: []jobevent.AncestorProcess{
				{ExecPath: "/bin/bash", Argv: []string{"bash", "-c", "Bearer abc123"}},
			},
		},
	}
}

func testHitEntry() *observations.HitEntry {
	identity := testRuleIdentity()
	return &observations.HitEntry{
		Identity:  identity,
		Action:    string(rule.RuleActionDetect),
		MaxAlerts: 2,
	}
}

func testRuleIdentity() rule.RuleIdentity {
	return rule.RuleIdentity{RulesetID: "set", RuleID: "curl_token"}
}

func testScopeLogContext() ScopeLogContext {
	return ScopeLogContext{
		Identity:       jobcontext.GitHubJobIdentity("github.com", "acme/project", "123", "test", "1", "runner"),
		Metadata:       jobcontext.JobMetadata{},
		RunnerType:     "machine",
		Scope:          jobcontext.ScopeTypeProject,
		ConfigRevision: "config-rev",
	}
}

func testLogTime() time.Time {
	return time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
}

func TestNewLogIDReturnsUUID(t *testing.T) {
	t.Parallel()

	id := newLogID()
	if _, err := uuid.Parse(id); err != nil {
		t.Fatalf("parse log id %q: %v", id, err)
	}
}

func TestUint32CounterClampsNegativeAndOverflow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   int64
		want uint32
	}{
		{name: "negative", in: -1, want: 0},
		{name: "zero", in: 0, want: 0},
		{name: "positive", in: 42, want: 42},
		{name: "overflow", in: 1 << 33, want: math.MaxUint32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uint32Counter(tt.in); got != tt.want {
				t.Fatalf("uint32Counter(%d): got %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestComponentLoggerHandlesNilLogger(t *testing.T) {
	t.Parallel()

	logger := componentLogger(nil, "unit")
	if logger == nil {
		t.Fatal("component logger: got nil")
	}
	var buf strings.Builder
	logger = componentLogger(slog.New(slog.NewTextHandler(&buf, nil)), "unit")
	logger.Info("hello")
	if !strings.Contains(buf.String(), "component=unit") {
		t.Fatalf("component attr missing from log line: %q", buf.String())
	}
}
