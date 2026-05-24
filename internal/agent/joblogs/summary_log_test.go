package joblogs

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

func TestMarshalSummaryLogEntryBuildsFinalSummary(t *testing.T) {
	t.Parallel()

	payload, err := MarshalSummaryLogEntry(SummaryLogInput{
		ScopeLogContext: testScopeLogContext(),
		RuleModifiers: []rule.RuleModifier{
			{ModifierID: "mod-a", Revision: "mod-rev"},
			{Revision: "ignored-empty-id"},
		},
		ResolvedRules: rule.ResolvedRules{Rules: []rule.ResolvedRule{
			{
				RulesetID:        "set-a",
				RulesetRevision:  "rules-rev",
				CanonicalRuleID:  rule.RuleIdentity{RulesetID: "set-a", RuleID: "detect_curl"}.CanonicalRuleID(),
				Rule:             rule.Rule{RuleID: "detect_curl"},
				PredefinedLists:  map[string][]string{"bins": {"curl"}},
				AppliedModifiers: nil,
			},
			{
				RulesetID:       "set-a",
				RulesetRevision: "rules-rev",
				Rule:            rule.Rule{RuleID: "detect_wget"},
			},
			{
				RulesetID:       "set-a",
				RulesetRevision: "new-rules-rev",
				Rule:            rule.Rule{RuleID: "detect_zsh"},
			},
			{RulesetRevision: "ignored-empty-ruleset"},
		}},
		Snapshot: observations.StateSnapshot{
			Counters: observations.StateCountersSnapshot{
				EventsTotal:   12,
				EventsDropped: -1,
			},
			ObservationNetwork: observations.NetworkObservationSnapshot{
				Records: []observations.NetworkObservationRecord{
					{RemoteIP: "203.0.113.10", RemotePort: 443, Protocol: "tcp"},
					{RemoteIP: "", RemotePort: 443, Protocol: "tcp"},
				},
			},
			ObservationDomain: observations.DomainObservationSnapshot{
				Records: []observations.DomainObservationRecord{
					{Domain: "example.com"},
					{Domain: ""},
				},
			},
			Hits: observations.HitSnapshot{
				{
					RulesetID:       "set-a",
					RuleID:          "detect_curl",
					RulesetRevision: "rules-rev",
					Action:          string(rule.RuleActionDetect),
					HitCount:        3,
				},
				{
					RulesetID:       "set-a",
					RuleID:          "terminate_nc",
					RulesetRevision: "rules-rev",
					Action:          string(rule.RuleActionTerminate),
					HitCount:        2,
				},
				{
					RulesetID:       "set-a",
					RuleID:          "collect_shell",
					RulesetRevision: "rules-rev",
					Action:          string(rule.RuleActionCollect),
					HitCount:        1,
				},
			},
		},
		FinalizeReason: "job_finished",
		FinalizedAt:    testLogTime(),
	})
	if err != nil {
		t.Fatalf("marshal summary log: %v", err)
	}

	var got logv1.SummaryLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal summary log: %v", err)
	}
	if got.GetTimestamp().AsTime() != testLogTime() {
		t.Fatalf("timestamp: got %s, want %s", got.GetTimestamp().AsTime(), testLogTime())
	}
	if got.GetJob().GetProjectPath() != "acme/project" {
		t.Fatalf("job project path: got %q", got.GetJob().GetProjectPath())
	}
	if got.GetScope() != "project" {
		t.Fatalf("scope: got %q, want project", got.GetScope())
	}
	if got.GetConfigRevision() != "config-rev" {
		t.Fatalf("config revision: got %q", got.GetConfigRevision())
	}
	if got.GetEventsTotal() != 12 || got.GetEventsDropped() != 0 {
		t.Fatalf("event counters: got total=%d dropped=%d", got.GetEventsTotal(), got.GetEventsDropped())
	}
	if len(got.GetRulesets()) != 2 {
		t.Fatalf("rulesets: got %#v, want 2 unique ruleset/revision pairs", got.GetRulesets())
	}
	if got.GetRulesets()[0].GetRulesetId() != "set-a" || got.GetRulesets()[0].GetRevision() != "rules-rev" {
		t.Fatalf("first ruleset: got %#v", got.GetRulesets()[0])
	}
	if got.GetRulesets()[1].GetRevision() != "new-rules-rev" {
		t.Fatalf("second ruleset revision: got %q", got.GetRulesets()[1].GetRevision())
	}
	if len(got.GetRuleModifiers()) != 1 || got.GetRuleModifiers()[0].GetModifierId() != "mod-a" {
		t.Fatalf("rule modifiers: got %#v", got.GetRuleModifiers())
	}
	if got.GetNetworkConnects()[0] != "203.0.113.10" {
		t.Fatalf("network connects: got %#v", got.GetNetworkConnects())
	}
	if got.GetDomains()[0] != "example.com" {
		t.Fatalf("domains: got %#v", got.GetDomains())
	}
	if len(got.GetDetections()) != 3 ||
		got.GetDetections()[0].GetRulesetId() != "set-a" ||
		got.GetDetections()[0].GetRuleId() != "detect_curl" ||
		got.GetDetections()[0].GetCount() != 3 {
		t.Fatalf("detections: got %#v", got.GetDetections())
	}
	if got.GetDetections()[1].GetAction() != string(rule.RuleActionTerminate) ||
		got.GetDetections()[2].GetAction() != string(rule.RuleActionCollect) {
		t.Fatalf("detection actions: got %#v", got.GetDetections())
	}
	if got.GetFinalizeReason() != "job_finished" {
		t.Fatalf("finalize reason: got %q", got.GetFinalizeReason())
	}
}

func TestMarshalSummaryLogEntryEmitsExplicitZeroCounters(t *testing.T) {
	t.Parallel()

	payload, err := MarshalSummaryLogEntry(SummaryLogInput{ScopeLogContext: testScopeLogContext()})
	if err != nil {
		t.Fatalf("marshal summary log: %v", err)
	}
	raw := string(payload)
	if !strings.Contains(raw, `"events_total":0`) {
		t.Fatalf("events_total: want explicit 0 in JSON, got %s", raw)
	}
	if !strings.Contains(raw, `"events_dropped":0`) {
		t.Fatalf("events_dropped: want explicit 0 in JSON, got %s", raw)
	}
}

func TestMarshalSummaryLogEntryStampsLogTypeAndVersions(t *testing.T) {
	t.Parallel()

	payload, err := MarshalSummaryLogEntry(SummaryLogInput{ScopeLogContext: testScopeLogContext()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got logv1.SummaryLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.GetLogType() != string(logtype.Summary) {
		t.Errorf("log_type: got %q, want %q", got.GetLogType(), string(logtype.Summary))
	}
	if got.GetSchemaVersion() != "v1" {
		t.Errorf("schema_version: got %q, want %q", got.GetSchemaVersion(), "v1")
	}
	if got.GetAgentVersion() != version.Current {
		t.Errorf("agent_version: got %q, want %q", got.GetAgentVersion(), version.Current)
	}
}

func TestMarshalSummaryLogEntryComputesDuration(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)
	end := start.Add(5 * time.Minute)
	payload, err := MarshalSummaryLogEntry(SummaryLogInput{
		ScopeLogContext: testScopeLogContext(),
		StartedAt:       start,
		FinalizedAt:     end,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got logv1.SummaryLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.GetStartTime().AsTime().Equal(start) {
		t.Errorf("start_time: got %v, want %v", got.GetStartTime().AsTime(), start)
	}
	if !got.GetEndTime().AsTime().Equal(end) {
		t.Errorf("end_time: got %v, want %v", got.GetEndTime().AsTime(), end)
	}
	if got.GetDurationS() != 300 {
		t.Errorf("duration_s: got %d, want 300", got.GetDurationS())
	}
}

func TestMarshalSummaryLogEntryOmitsLifecycleWhenStartedAtZero(t *testing.T) {
	t.Parallel()

	payload, err := MarshalSummaryLogEntry(SummaryLogInput{
		ScopeLogContext: testScopeLogContext(),
		FinalizedAt:     time.Date(2026, 5, 23, 10, 5, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(payload)
	if strings.Contains(raw, `"start_time"`) {
		t.Errorf("start_time should be omitted when StartedAt is zero: %s", raw)
	}
	if strings.Contains(raw, `"duration_s"`) {
		t.Errorf("duration_s should be omitted when StartedAt is zero: %s", raw)
	}
}

func TestMarshalSummaryLogEntryConfigRevisionAbsentSentinel(t *testing.T) {
	t.Parallel()

	scope := testScopeLogContext()
	scope.ConfigRevision = ""
	payload, err := MarshalSummaryLogEntry(SummaryLogInput{ScopeLogContext: scope})
	if err != nil {
		t.Fatalf("marshal summary log: %v", err)
	}
	if !strings.Contains(string(payload), `"config_revision":"(none)"`) {
		t.Fatalf("config_revision: want explicit %q sentinel in JSON, got %s", AbsentSentinel, payload)
	}
}

func TestMarshalSummaryLogEntryDefaultsFinalizedAt(t *testing.T) {
	t.Parallel()

	before := time.Now().Add(-time.Second)
	payload, err := MarshalSummaryLogEntry(SummaryLogInput{ScopeLogContext: testScopeLogContext()})
	if err != nil {
		t.Fatalf("marshal summary log: %v", err)
	}
	after := time.Now().Add(time.Second)

	var got logv1.SummaryLogEntry
	if err := protojson.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal summary log: %v", err)
	}
	timestamp := got.GetTimestamp().AsTime()
	if timestamp.Before(before) || timestamp.After(after) {
		t.Fatalf("default timestamp: got %s, want between %s and %s", timestamp, before, after)
	}
}
