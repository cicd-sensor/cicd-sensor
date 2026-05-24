package agent_test

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/evaluation"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestEvaluateEvent_MaxAlertsCapsDetectionEmission(t *testing.T) {
	t.Parallel()

	stream := &recordingDetectionOutput{}
	hostScope := jobscope.NewHost()
	attachRecordingDetectionOutput(t, hostScope, stream)
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "detect",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
			MaxAlerts: 2,
		}},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	closeRecordingOutputs(t, hostScope)

	entries := stream.Entries(t)
	if len(entries) != 2 {
		t.Fatalf("detection entries: got %d, want 2", len(entries))
	}
	truncations := map[string]int{}
	for _, entry := range entries {
		truncations[entry.GetRuleAlertTruncation()]++
	}
	if truncations[""] != 1 {
		t.Fatalf("empty truncation count: got %d, want 1 (entries=%#v)", truncations[""], entries)
	}
	if truncations[resultdoc.AlertTruncationMaxAlertsReached] != 1 {
		t.Fatalf("max_alerts truncation count: got %d, want 1 (entries=%#v)", truncations[resultdoc.AlertTruncationMaxAlertsReached], entries)
	}
	snapshot := hostScope.ObservationSnapshot()
	if len(detectHits(snapshot)) != 1 {
		t.Fatalf("detect summary len: got %d, want 1", len(detectHits(snapshot)))
	}
	if detectHits(snapshot)[0].HitCount != 3 {
		t.Fatalf("hit_count: got %d, want 3", detectHits(snapshot)[0].HitCount)
	}
}

func TestEvaluateEvent_MaxAlertsUsesScopeDefault(t *testing.T) {
	t.Parallel()

	stream := &recordingDetectionOutput{}
	hostScope := jobscope.NewHost()
	hostScope.DefaultMaxAlertsPerRule = 1
	attachRecordingDetectionOutput(t, hostScope, stream)
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "detect",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)
	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	closeRecordingOutputs(t, hostScope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("detection entries: got %d, want 1", len(entries))
	}
	if entries[0].GetRuleAlertTruncation() != resultdoc.AlertTruncationMaxAlertsReached {
		t.Fatalf("truncation: got %q, want %q", entries[0].GetRuleAlertTruncation(), resultdoc.AlertTruncationMaxAlertsReached)
	}
}

func TestEvaluateEvent_TerminateBypassesMaxAlerts(t *testing.T) {
	t.Parallel()

	stream := &recordingDetectionOutput{}
	hostScope := jobscope.NewHost()
	attachRecordingDetectionOutput(t, hostScope, stream)
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "terminate",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionTerminate,
			MaxAlerts: 1,
		}},
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)
	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	closeRecordingOutputs(t, hostScope)

	entries := stream.Entries(t)
	if len(entries) != 2 {
		t.Fatalf("detection entries: got %d, want 2", len(entries))
	}
	for i, entry := range entries {
		if entry.GetRuleAlertTruncation() != "" {
			t.Fatalf("entry[%d] truncation: got %q, want empty", i, entry.GetRuleAlertTruncation())
		}
	}
}
