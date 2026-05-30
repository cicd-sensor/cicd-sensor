package agent_test

import (
	"slices"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/evaluation"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestEvaluateEvent_TriggersCorrelationAfterSingleHit(t *testing.T) {
	t.Parallel()

	hostScope := newCorrelationScope("host-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
		},
	})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)

	snapshot := hostScope.ObservationSnapshot()
	if got := len(detectHits(snapshot)); got != 1 {
		t.Fatalf("detect hit count: got %d, want 1", got)
	}
	if got := len(preventHits(snapshot)); got != 1 {
		t.Fatalf("prevent hit count: got %d, want 1", got)
	}
	if got := summaryRuleRef(preventHits(snapshot)[0]); got != "host-set/corr" {
		t.Fatalf("correlation rule_id: got %q, want %q", got, "host-set/corr")
	}
}

func TestEvaluateEvent_CorrelationThresholdAcrossReferencedRules(t *testing.T) {
	t.Parallel()

	hostScope := newCorrelationScope("host-set", []rule.Rule{
		{
			RuleID:    "x",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "y",
			EventType: jobevent.NetworkConnect,
			Condition: `protocol == "tcp"`,
			Action:    rule.RuleActionCollect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["x"].total_count >= 2 && rule["y"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
		},
	})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	event := testDispatchEvent("/usr/bin/curl", "example.com", 443)

	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	if got := len(preventHits(hostScope.ObservationSnapshot())); got != 0 {
		t.Fatalf("prevent hits after first event: got %d, want 0", got)
	}

	evaluateTestRules(testCtx, eval, event, hostScope, nil, testLogger)
	if got := len(preventHits(hostScope.ObservationSnapshot())); got != 1 {
		t.Fatalf("prevent hits after second event: got %d, want 1", got)
	}
}

func TestEvaluateEvent_CorrelationAcceptsDotAndBracketSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		condition string
		wantIDs   []string
	}{
		{
			name:      "dot_form",
			condition: `rule.suspicious_bin_exec.total_count >= 1`,
			wantIDs:   []string{"host-set/credential_file_open", "host-set/suspicious_bin_exec", "host-set/corr"},
		},
		{
			name:      "bracket_form",
			condition: `rule["suspicious_bin_exec"].total_count >= 1`,
			wantIDs:   []string{"host-set/credential_file_open", "host-set/suspicious_bin_exec", "host-set/corr"},
		},
		{
			name:      "mixed_dot_and_bracket",
			condition: `rule.suspicious_bin_exec.total_count >= 1 && rule["credential_file_open"].total_count >= 1`,
			wantIDs:   []string{"host-set/credential_file_open", "host-set/corr", "host-set/suspicious_bin_exec"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hostScope := newCorrelationScope("host-set", []rule.Rule{
				{
					RuleID:    "suspicious_bin_exec",
					EventType: jobevent.NetworkConnect,
					Condition: `protocol == "tcp"`,
					Action:    rule.RuleActionDetect,
				},
				{
					RuleID:    "credential_file_open",
					EventType: jobevent.NetworkConnect,
					Condition: `remote_ip == "example.com"`,
					Action:    rule.RuleActionDetect,
				},
				{
					RuleID:    "corr",
					Type:      "correlation",
					Condition: tt.condition,
					Action:    rule.RuleActionDetect,
				},
			})

			eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
			evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)

			snapshot := hostScope.ObservationSnapshot()
			if got := len(detectHits(snapshot)); got != len(tt.wantIDs) {
				t.Fatalf("detect hit count: got %d, want %d", got, len(tt.wantIDs))
			}

			gotIDs := make([]string, 0, len(detectHits(snapshot)))
			for _, hit := range detectHits(snapshot) {
				gotIDs = append(gotIDs, summaryRuleRef(hit))
			}
			wantIDs := slices.Clone(tt.wantIDs)
			slices.Sort(gotIDs)
			slices.Sort(wantIDs)
			if !slices.Equal(gotIDs, wantIDs) {
				t.Fatalf("detect hit ids: got %#v, want %#v", gotIDs, wantIDs)
			}
		})
	}
}

func TestEvaluateEvent_CorrelationCollectActionFeedsCollectBucket(t *testing.T) {
	t.Parallel()

	hostScope := newCorrelationScope("host-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionCollect,
		},
	})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)

	snapshot := hostScope.ObservationSnapshot()
	if got := len(collectHits(snapshot)); got != 1 {
		t.Fatalf("collect hit count: got %d, want 1", got)
	}
	if got := summaryRuleRef(collectHits(snapshot)[0]); got != "host-set/corr" {
		t.Fatalf("collect correlation rule_id: got %q, want %q", got, "host-set/corr")
	}
}

func TestEvaluateEvent_Correlations_EmitsDetectionLog(t *testing.T) {
	t.Parallel()

	stream := &recordingDetectionOutput{}
	hostScope := newCorrelationScope("host-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
		},
	})
	attachRecordingDetectionOutput(t, hostScope, stream)

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)
	closeRecordingOutputs(t, hostScope)

	entries := stream.Entries(t)
	if len(entries) != 3 {
		t.Fatalf("detection entries: got %d, want 3", len(entries))
	}
	corrIdx := slices.IndexFunc(entries, func(entry *logv1beta1.DetectionLogEntry) bool {
		return detectionRuleRef(entry) == "host-set/corr"
	})
	if corrIdx < 0 {
		t.Fatalf("correlation entry not found: got rule_ids %#v", detectionRuleIDs(entries))
	}
	if got := detectionRuleIDCount(entries, "host-set/corr"); got != 1 {
		t.Fatalf("correlation detection entries: got %d, want 1", got)
	}
}

func detectionRuleIDs(entries []*logv1beta1.DetectionLogEntry) []string {
	ruleIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		ruleIDs = append(ruleIDs, detectionRuleRef(entry))
	}
	return ruleIDs
}

func detectionRuleIDCount(entries []*logv1beta1.DetectionLogEntry, ruleID string) int {
	count := 0
	for _, entry := range entries {
		if detectionRuleRef(entry) == ruleID {
			count++
		}
	}
	return count
}

func summaryRuleRef(hit observations.HitSummary) string {
	return hit.RulesetID + "/" + hit.RuleID
}

func detectionRuleRef(entry *logv1beta1.DetectionLogEntry) string {
	return entry.GetRulesetId() + "/" + entry.GetRuleId()
}

func hitRecordRuleRef(entry resultdoc.HitRecord) string {
	return entry.RulesetID + "/" + entry.RuleID
}

func TestEvaluateEvent_Correlations_RuntimeEventOmitsHits(t *testing.T) {
	t.Parallel()

	stream := &recordingRuntimeEventOutput{}
	hostScope := newCorrelationScope("host-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
		},
	})
	attachRecordingRuntimeEventOutput(t, hostScope, stream)

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)
	closeRecordingOutputs(t, hostScope)

	entries := stream.Entries(t)
	if len(entries) != 1 {
		t.Fatalf("runtime event entries: got %d, want 1", len(entries))
	}
	if entries[0].GetEvent().GetId() == "" {
		t.Fatal("event id missing")
	}
}

func TestEvaluateEvent_TriggersMultipleCorrelationsFromOneEvent(t *testing.T) {
	t.Parallel()

	hostScope := newCorrelationScope("host-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr-detect",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr-terminate",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
		},
	})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)

	snapshot := hostScope.ObservationSnapshot()
	if got := len(detectHits(snapshot)); got != 2 {
		t.Fatalf("detect hit count: got %d, want 2", got)
	}
	if got := len(preventHits(snapshot)); got != 1 {
		t.Fatalf("prevent hit count: got %d, want 1", got)
	}
}

func TestEvaluateEvent_CorrelationFiresOncePerScope(t *testing.T) {
	t.Parallel()

	hostScope := newCorrelationScope("host-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "unrelated",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "other.example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionDetect,
		},
	})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "other.example.com", 443), hostScope, nil, testLogger)

	snapshot := hostScope.ObservationSnapshot()
	var correlationHit *observations.HitSummary
	for i := range detectHits(snapshot) {
		if summaryRuleRef(detectHits(snapshot)[i]) == "host-set/corr" {
			correlationHit = &detectHits(snapshot)[i]
			break
		}
	}
	if correlationHit == nil {
		t.Fatal("expected correlation hit")
	}
	if got := correlationHit.HitCount; got != 1 {
		t.Fatalf("correlation hit_count: got %d, want 1", got)
	}
}

func TestEvaluateEvent_CorrelationFeedsHostAndProjectScopes(t *testing.T) {
	t.Parallel()

	hostScope := newCorrelationScope("shared-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
		},
	})
	projectScope := newProjectScopeWithRules("shared-set", []rule.Rule{
		{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		},
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
		},
	})

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(projectScope))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, projectScope, testLogger)

	if got := len(preventHits(hostScope.ObservationSnapshot())); got != 1 {
		t.Fatalf("host prevent hit count: got %d, want 1", got)
	}
	if got := len(preventHits(projectScope.ObservationSnapshot())); got != 1 {
		t.Fatalf("project prevent hit count: got %d, want 1", got)
	}
}

func TestEvaluateEvent_CorrelationAggregatesIdentityCollisionHits(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.ResolvedRules = rule.ResolvedRules{
		Rules: []rule.ResolvedRule{
			{
				CanonicalRuleID: "shared-set/x",
				Rule: rule.Rule{
					RuleID:    "x",
					EventType: jobevent.NetworkConnect,
					Condition: `remote_ip == "example.com"`,
					Action:    rule.RuleActionDetect,
				},
				RulesetID: "shared-set",
			},
			{
				CanonicalRuleID: "shared-set/x",
				Rule: rule.Rule{
					RuleID:    "x",
					EventType: jobevent.NetworkConnect,
					Condition: `protocol == "tcp"`,
					Action:    rule.RuleActionCollect,
				},
				RulesetID: "shared-set",
			},
			{
				CanonicalRuleID: "shared-set/corr",
				Rule: rule.Rule{
					RuleID:    "corr",
					Type:      "correlation",
					Condition: `rule["x"].total_count >= 2`,
					Action:    rule.RuleActionTerminate,
				},
				RulesetID: "shared-set",
			},
		},
		Warnings: []rule.ResolveWarning{{
			Kind:     "duplicate_identity_diff_content",
			Identity: rule.RuleIdentity{RulesetID: "shared-set", RuleID: "x"},
		}},
	}

	eval := evaluation.NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	evaluateTestRules(testCtx, eval, testDispatchEvent("/usr/bin/curl", "example.com", 443), hostScope, nil, testLogger)

	if got := len(preventHits(hostScope.ObservationSnapshot())); got != 1 {
		t.Fatalf("prevent hit count: got %d, want 1", got)
	}
}

func newCorrelationScope(setIdentity string, rules []rule.Rule) *jobscope.JobScopeState {
	scope := jobscope.NewHost()
	scope.RuleSets = []rule.RuleSet{{
		RulesetID: setIdentity,
		Rules:     rules,
	}}
	scope.ResolveRules(jobcontext.JobIdentity{})
	return scope
}

func newProjectScopeWithRules(setIdentity string, rules []rule.Rule) *jobscope.JobScopeState {
	scope := jobscope.NewProject()
	scope.RuleSets = []rule.RuleSet{{
		RulesetID: setIdentity,
		Rules:     rules,
	}}
	scope.ResolveRules(jobcontext.JobIdentity{})
	return scope
}
