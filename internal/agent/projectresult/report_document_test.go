package projectresult

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestBuildJobEventSummaryForReportSanitizesRetainedEvent(t *testing.T) {
	t.Parallel()

	doc := BuildJobEventSummaryForReport(ReportDocumentInput{
		Identity:       jobcontext.GitHubJobIdentity("github.com", "acme/project", "123", "test", "1", "runner"),
		Metadata:       jobcontext.JobMetadata{},
		RunnerType:     "machine",
		StartedAt:      testLogTime().Add(-time.Minute),
		GeneratedAt:    testLogTime(),
		FinalizeReason: "test",
		Snapshot: observations.StateSnapshot{
			Hits: observations.HitSnapshot{{
				Identity:          testRuleIdentity(),
				RulesetID:         "set",
				RuleID:            "curl_token",
				Action:            string(rule.RuleActionDetect),
				HitCount:          1,
				AlertEventRecords: []jobevent.EventRecord{eventWithSecretArgv()},
			}},
		},
	})

	if len(doc.Hits) != 1 || len(doc.Hits[0].AlertEvents) != 1 || doc.Hits[0].AlertEvents[0].Process == nil {
		t.Fatalf("hits: got %#v, want one process detail", doc.Hits)
	}
	ev := doc.Hits[0].AlertEvents[0]
	if got, want := ev.Process.Argv[1], "<redacted>"; got != want {
		t.Fatalf("report argv: got %q, want %q", got, want)
	}
	if got, want := ev.Process.StartBoottime, uint64(200); got != want {
		t.Fatalf("report start_boottime: got %d, want %d", got, want)
	}
	if got, want := ev.Process.Ancestors[0].Argv[2], "<redacted>"; got != want {
		t.Fatalf("report ancestor argv: got %q, want %q", got, want)
	}
	if got, want := doc.RunnerType, "machine"; got != want {
		t.Fatalf("runner type: got %q, want %q", got, want)
	}
}

func TestBuildJobEventSummaryForReportBuildsPassSummary(t *testing.T) {
	t.Parallel()

	doc := BuildJobEventSummaryForReport(ReportDocumentInput{
		Identity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
		Metadata: jobcontext.JobMetadata{
			CommitSHA: "abc123",
		},
		StartedAt:      testLogTime().Add(-2 * time.Minute),
		GeneratedAt:    testLogTime(),
		FinalizeReason: "project_result",
		ResolvedRules: rule.ResolvedRules{
			Rules: []rule.ResolvedRule{
				resolvedRule("set", "curl_token", "Curl token"),
				resolvedRule("set", "bash_exec", "Bash exec"),
			},
			Warnings: []rule.ResolveWarning{{Kind: "duplicate_rule"}},
		},
		Snapshot: observations.StateSnapshot{
			ObservationDomain: observations.DomainObservationSnapshot{Records: []observations.DomainObservationRecord{{
				Domain:               "example.com",
				ProcessOverflowCount: 1,
				Processes: []observations.ProcessContext{{
					PID:           100,
					StartBoottime: 200,
					ExecPath:      "/usr/bin/dig",
					Ancestors: []observations.ProcessAncestorContext{{
						ExecPath: "/bin/bash",
					}},
				}},
			}}},
			ObservationNetwork: observations.NetworkObservationSnapshot{Records: []observations.NetworkObservationRecord{{
				RemoteIP:             "203.0.113.10",
				RemotePort:           443,
				Protocol:             "tcp",
				ProcessOverflowCount: 2,
				Processes: []observations.ProcessContext{{
					PID:           101,
					StartBoottime: 201,
					ExecPath:      "/usr/bin/curl",
				}},
			}}},
		},
	})

	if doc.ResultSummary.Result != resultdoc.ResultPassed {
		t.Fatalf("result: got %q, want passed", doc.ResultSummary.Result)
	}
	if doc.RulesSummary.RuleCount != 2 || doc.RulesSummary.WarningsCount != 1 {
		t.Fatalf("rules summary: got %+v", doc.RulesSummary)
	}
	if len(doc.Hits) != 0 {
		t.Fatalf("hits: got %d, want 0", len(doc.Hits))
	}
	if len(doc.NetworkConnections) != 1 || doc.NetworkConnections[0].RemoteIP != "203.0.113.10" {
		t.Fatalf("network connections: got %#v", doc.NetworkConnections)
	}
	if got, want := doc.NetworkConnections[0].Processes[0].StartBoottime, uint64(201); got != want {
		t.Fatalf("network process start_boottime: got %d, want %d", got, want)
	}
	if got, want := doc.NetworkConnections[0].ProcessOverflowCount, int64(2); got != want {
		t.Fatalf("network process overflow: got %d, want %d", got, want)
	}
	if len(doc.DomainObservations) != 1 || doc.DomainObservations[0].Domain != "example.com" {
		t.Fatalf("domain observations: got %#v", doc.DomainObservations)
	}
	if got, want := doc.DomainObservations[0].Processes[0].StartBoottime, uint64(200); got != want {
		t.Fatalf("domain process start_boottime: got %d, want %d", got, want)
	}
	if got, want := doc.DomainObservations[0].Processes[0].Ancestors[0].ExecPath, "/bin/bash"; got != want {
		t.Fatalf("domain observation ancestor exec path: got %q, want %q", got, want)
	}
	if got, want := doc.DomainObservations[0].ProcessOverflowCount, int64(1); got != want {
		t.Fatalf("domain process overflow: got %d, want %d", got, want)
	}
	if !doc.StartedAt.Equal(testLogTime().Add(-2*time.Minute)) || !doc.GeneratedAt.Equal(testLogTime()) {
		t.Fatalf("timestamps: started=%s generated=%s", doc.StartedAt, doc.GeneratedAt)
	}
}

func TestBuildJobEventSummaryForReportBuildsHitsWithTruncation(t *testing.T) {
	t.Parallel()

	identity := testRuleIdentity()
	doc := BuildJobEventSummaryForReport(ReportDocumentInput{
		Identity: jobcontext.GitHubJobIdentity("github.com", "acme/project", "123", "test", "1", "runner"),
		ResolvedRules: rule.ResolvedRules{
			Rules: []rule.ResolvedRule{
				resolvedRule(identity.RulesetID, identity.RuleID, "Curl token"),
			},
		},
		Snapshot: observations.StateSnapshot{
			Hits: observations.HitSnapshot{{
				Identity:  identity,
				RulesetID: identity.RulesetID,
				RuleID:    identity.RuleID,
				Action:    string(rule.RuleActionDetect),
				HitCount:  3,
				MaxAlerts: 2,
				AlertEventRecords: []jobevent.EventRecord{
					eventWithPayload("first"),
					eventWithPayload("second"),
				},
			}},
		},
	})

	if doc.ResultSummary.Result != resultdoc.ResultDetected {
		t.Fatalf("result: got %q, want detected", doc.ResultSummary.Result)
	}
	if len(doc.Hits) != 1 {
		t.Fatalf("hits: got %d, want 1 (per-rule)", len(doc.Hits))
	}
	h := doc.Hits[0]
	if h.RuleName != "Curl token" || h.RuleType != "event" ||
		h.RuleCondition != `process.exec_path.endsWith("curl")` {
		t.Fatalf("rule metadata: got %+v", h)
	}
	if h.HitCount != 3 || h.MaxAlerts != 2 || len(h.AlertEvents) != 2 {
		t.Fatalf("counts: got hit_count=%d max_alerts=%d alert_events=%d, want 3/2/2",
			h.HitCount, h.MaxAlerts, len(h.AlertEvents))
	}
	if got := h.AlertEvents[1].Payload["label"]; got != "second" {
		t.Fatalf("payload: got %v, want second", got)
	}
}

func TestBuildJobEventSummaryForReportIncludesAllHitActions(t *testing.T) {
	t.Parallel()

	doc := BuildJobEventSummaryForReport(ReportDocumentInput{
		Identity: jobcontext.GitHubJobIdentity("github.com", "acme/project", "123", "test", "1", "runner"),
		ResolvedRules: rule.ResolvedRules{
			Rules: []rule.ResolvedRule{
				resolvedRule("set", "detect_rule", "Detect rule"),
				resolvedRule("set", "terminate_rule", "Terminate rule"),
				resolvedRule("set", "collect_rule", "Collect rule"),
			},
		},
		Snapshot: observations.StateSnapshot{
			Hits: observations.HitSnapshot{
				{
					Identity:          rule.RuleIdentity{RulesetID: "set", RuleID: "detect_rule"},
					RulesetID:         "set",
					RuleID:            "detect_rule",
					Action:            string(rule.RuleActionDetect),
					HitCount:          1,
					AlertEventRecords: []jobevent.EventRecord{eventWithPayload("detect")},
				},
				{
					Identity:          rule.RuleIdentity{RulesetID: "set", RuleID: "terminate_rule"},
					RulesetID:         "set",
					RuleID:            "terminate_rule",
					Action:            string(rule.RuleActionTerminate),
					HitCount:          1,
					AlertEventRecords: []jobevent.EventRecord{eventWithPayload("terminate")},
				},
				{
					Identity:          rule.RuleIdentity{RulesetID: "set", RuleID: "collect_rule"},
					RulesetID:         "set",
					RuleID:            "collect_rule",
					Action:            string(rule.RuleActionCollect),
					HitCount:          1,
					AlertEventRecords: []jobevent.EventRecord{eventWithPayload("collect")},
				},
			},
		},
	})

	if doc.ResultSummary.Result != resultdoc.ResultTerminated {
		t.Fatalf("result: got %q, want terminated", doc.ResultSummary.Result)
	}
	if got := len(doc.Hits); got != 3 {
		t.Fatalf("hits length: got %d, want 3: %#v", got, doc.Hits)
	}
	if got := doc.Hits[0].Action; got != string(rule.RuleActionDetect) {
		t.Fatalf("first hit action: got %q, want detect", got)
	}
	if got := doc.Hits[1].Action; got != string(rule.RuleActionTerminate) {
		t.Fatalf("second hit action: got %q, want terminate", got)
	}
	if got := doc.Hits[2].Action; got != string(rule.RuleActionCollect) {
		t.Fatalf("third hit action: got %q, want collect", got)
	}
}

func TestBuildJobEventSummaryForReportIncludesCorrelationRuleMetadata(t *testing.T) {
	t.Parallel()

	identity := rule.RuleIdentity{RulesetID: "set", RuleID: "correlated"}
	doc := BuildJobEventSummaryForReport(ReportDocumentInput{
		ResolvedRules: rule.ResolvedRules{Rules: []rule.ResolvedRule{{
			CanonicalRuleID: identity.CanonicalRuleID(),
			RulesetID:       identity.RulesetID,
			Rule: rule.Rule{
				RuleID:    identity.RuleID,
				RuleName:  "Correlated signal",
				Type:      "correlation",
				Condition: "rule.first.total_count >= 1 && rule.second.total_count >= 1",
				Action:    rule.RuleActionDetect,
			},
		}}},
		Snapshot: observations.StateSnapshot{
			Hits: observations.HitSnapshot{{
				Identity:          identity,
				RulesetID:         identity.RulesetID,
				RuleID:            identity.RuleID,
				Action:            string(rule.RuleActionDetect),
				HitCount:          1,
				AlertEventRecords: []jobevent.EventRecord{eventWithPayload("correlation")},
			}},
		},
	})

	if got := len(doc.Hits); got != 1 {
		t.Fatalf("hits length: got %d, want 1", got)
	}
	hit := doc.Hits[0]
	if hit.RuleType != "correlation" {
		t.Fatalf("rule_type: got %q, want correlation", hit.RuleType)
	}
	if hit.RuleCondition != "rule.first.total_count >= 1 && rule.second.total_count >= 1" {
		t.Fatalf("rule_condition: got %q", hit.RuleCondition)
	}
	if len(hit.AlertEvents) == 0 || hit.AlertEvents[0].EventType != jobevent.ProcessExec {
		t.Fatalf("alert event type: got %+v", hit.AlertEvents)
	}
}

func TestBuildJobEventSummaryForReportCollectOnlyKeepsPassResult(t *testing.T) {
	t.Parallel()

	doc := BuildJobEventSummaryForReport(ReportDocumentInput{
		Snapshot: observations.StateSnapshot{
			Hits: observations.HitSnapshot{{
				Identity:          rule.RuleIdentity{RulesetID: "set", RuleID: "collect_rule"},
				RulesetID:         "set",
				RuleID:            "collect_rule",
				Action:            string(rule.RuleActionCollect),
				HitCount:          1,
				AlertEventRecords: []jobevent.EventRecord{eventWithPayload("collect")},
			}},
		},
	})

	if got := doc.ResultSummary.Result; got != resultdoc.ResultPassed {
		t.Fatalf("result: got %q, want passed", got)
	}
	if got := len(doc.Hits); got != 1 {
		t.Fatalf("hits length: got %d, want 1", got)
	}
}

func TestBuildJobEventSummaryForReportEmitsEmptySlices(t *testing.T) {
	t.Parallel()

	doc := BuildJobEventSummaryForReport(ReportDocumentInput{
		Identity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
	})
	if doc.NetworkConnections == nil {
		t.Fatal("network connections slice: got nil, want empty slice")
	}
	if doc.DomainObservations == nil {
		t.Fatal("domain observations slice: got nil, want empty slice")
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := string(raw["network_connections"]); got != "[]" {
		t.Fatalf("network connections json: got %s, want []", got)
	}
	if got := string(raw["domain_observations"]); got != "[]" {
		t.Fatalf("domain observations json: got %s, want []", got)
	}
}

func eventWithSecretArgv() jobevent.EventRecord {
	return jobevent.EventRecord{
		ID:        "event-1",
		EventType: jobevent.ProcessExec,
		Timestamp: testLogTime(),
		Process: jobevent.ProcessSummary{
			PID:           100,
			StartBoottime: 200,
			ExecPath:      "/usr/bin/curl",
			Argv:          []string{"curl", "--token=supersecret"},
			Ancestors: []jobevent.AncestorProcess{
				{ExecPath: "/bin/bash", Argv: []string{"bash", "-c", "Bearer abc123"}},
			},
		},
	}
}

func eventWithPayload(label string) jobevent.EventRecord {
	event := eventWithSecretArgv()
	event.ID = "event-" + label
	event.Payload = map[string]any{"label": label}
	return event
}

func testRuleIdentity() rule.RuleIdentity {
	return rule.RuleIdentity{RulesetID: "set", RuleID: "curl_token"}
}

func testLogTime() time.Time {
	return time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
}

func resolvedRule(rulesetID, ruleID, name string) rule.ResolvedRule {
	identity := rule.RuleIdentity{RulesetID: rulesetID, RuleID: ruleID}
	return rule.ResolvedRule{
		CanonicalRuleID: identity.CanonicalRuleID(),
		RulesetID:       rulesetID,
		Rule: rule.Rule{
			RuleID:    ruleID,
			RuleName:  name,
			Condition: `process.exec_path.endsWith("curl")`,
			Action:    rule.RuleActionDetect,
		},
	}
}
