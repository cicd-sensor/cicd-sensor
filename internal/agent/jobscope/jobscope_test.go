package jobscope_test

import (
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestNewProject_InitializesRuntimeState(t *testing.T) {
	t.Parallel()

	scope := jobscope.NewProject()

	if scope.Type != jobcontext.ScopeTypeProject {
		t.Fatalf("scope type: got %q, want %q", scope.Type, jobcontext.ScopeTypeProject)
	}
	if scope.Observations == nil {
		t.Fatal("expected observations to be initialized")
	}
	snapshot := scope.ObservationSnapshot()
	if snapshot.Counters.EventsTotal != 0 || snapshot.Counters.EventsDropped != 0 {
		t.Fatalf("expected zero counters, got %+v", snapshot.Counters)
	}
}

func TestBuildJobEventSummaryForReportSanitizesRetainedEvent(t *testing.T) {
	t.Parallel()

	scope := jobscope.NewProject()
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	hit := observations.HitEntry{
		Identity:  rule.RuleIdentity{RulesetID: "set", RuleID: "curl_token"},
		Action:    string(rule.RuleActionDetect),
		MaxAlerts: 1,
	}
	event := jobevent.EventRecord{
		EventType: jobevent.ProcessExec,
		Timestamp: now,
		Process: jobevent.ProcessSummary{
			PID:      100,
			ExecPath: "/usr/bin/curl",
			Argv:     []string{"curl", "--token=supersecret"},
			Ancestors: []jobevent.AncestorProcess{
				{ExecPath: "/bin/bash", Argv: []string{"bash", "-c", "Bearer abc123"}},
			},
		},
	}

	scope.RecordHit(hit, event)

	snapshot := scope.ObservationSnapshot()
	if len(snapshot.Hits) != 1 || len(snapshot.Hits[0].AlertEventRecords) != 1 {
		t.Fatalf("expected 1 stored hit, got %#v", snapshot.Hits)
	}
	stored := snapshot.Hits[0].AlertEventRecords[0].Process
	if got, want := stored.Argv[1], "--token=supersecret"; got != want {
		t.Fatalf("stored argv: got %q, want %q", got, want)
	}

	doc := scope.BuildJobEventSummaryForReport(jobscope.ReportInputs{}, "test", now)
	if len(doc.Hits) != 1 || doc.Hits[0].Process == nil {
		t.Fatalf("expected 1 hit with process, got %#v", doc.Hits)
	}
	if got, want := doc.Hits[0].Process.Argv[1], "<redacted>"; got != want {
		t.Fatalf("report argv: got %q, want %q", got, want)
	}
	if got, want := doc.Hits[0].Process.Ancestors[0].Argv[2], "<redacted>"; got != want {
		t.Fatalf("report ancestor argv: got %q, want %q", got, want)
	}
}
