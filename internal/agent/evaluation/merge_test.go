package evaluation

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestNewEvaluationState_SharedRulesDedupesAndUnionsScopes(t *testing.T) {
	t.Parallel()

	host := &jobscope.JobScopeState{
		ResolvedRules: resolvedRules("shared-set", rule.Rule{
			RuleID:    "r1",
			Condition: `process.exec_path.endsWith("/bash")`,
			EventType: jobevent.ProcessExec,
			Action:    rule.RuleActionDetect,
		}),
	}
	project := &jobscope.JobScopeState{
		ResolvedRules: resolvedRules("shared-set", rule.Rule{
			RuleID:    "r1",
			Condition: `process.exec_path.endsWith("/bash")`,
			EventType: jobevent.ProcessExec,
			Action:    rule.RuleActionDetect,
		}),
	}

	got := NewEvaluationState(scopeResolvedRules(host), scopeResolvedRules(project))
	rules := got.RulesByType[jobevent.ProcessExec]
	if len(rules) != 1 {
		t.Fatalf("rule count: got %d, want 1", len(rules))
	}
	if !rules[0].FeedHost || !rules[0].FeedProject {
		t.Fatalf("scope routing: got host=%v project=%v, want both true", rules[0].FeedHost, rules[0].FeedProject)
	}
}

func TestNewEvaluationState_SharedRuleDifferentContentKeepsScopeVariants(t *testing.T) {
	t.Parallel()

	host := &jobscope.JobScopeState{
		ResolvedRules: resolvedRules("shared-set", rule.Rule{
			RuleID:    "r1",
			Condition: `process.exec_path.endsWith("/bash")`,
			EventType: jobevent.ProcessExec,
			Action:    rule.RuleActionTerminate,
		}),
	}
	project := &jobscope.JobScopeState{
		ResolvedRules: resolvedRules("shared-set", rule.Rule{
			RuleID:    "r1",
			Condition: `process.exec_path.endsWith("/bash")`,
			EventType: jobevent.ProcessExec,
			Action:    rule.RuleActionDetect,
		}),
	}

	got := NewEvaluationState(scopeResolvedRules(host), scopeResolvedRules(project))
	rules := got.RulesByType[jobevent.ProcessExec]
	if len(rules) != 2 {
		t.Fatalf("rule count: got %d, want 2", len(rules))
	}
	var sawHost, sawProject bool
	for _, compiled := range rules {
		switch {
		case compiled.Action == rule.RuleActionTerminate && compiled.FeedHost && !compiled.FeedProject:
			sawHost = true
		case compiled.Action == rule.RuleActionDetect && !compiled.FeedHost && compiled.FeedProject:
			sawProject = true
		}
	}
	if !sawHost || !sawProject {
		t.Fatalf("compiled rules: got %#v", rules)
	}
}

func TestNewEvaluationState_PredefinedListsParticipateInContentEquality(t *testing.T) {
	t.Parallel()

	ruleWithList := rule.Rule{
		RuleID:    "r1",
		Condition: `list.shells.exists(b, process.exec_path.endsWith(b))`,
		EventType: jobevent.ProcessExec,
		Action:    rule.RuleActionDetect,
	}
	host := &jobscope.JobScopeState{
		ResolvedRules: rule.ResolvedRules{
			Rules: []rule.ResolvedRule{{
				CanonicalRuleID: "shared-set/r1",
				Rule:            ruleWithList,
				RulesetID:       "shared-set",
				PredefinedLists: rule.PredefinedLists{"shells": {"bash"}},
				RulesetRevision: "rev-host",
			}},
		},
	}
	project := &jobscope.JobScopeState{
		ResolvedRules: rule.ResolvedRules{
			Rules: []rule.ResolvedRule{{
				CanonicalRuleID: "shared-set/r1",
				Rule:            ruleWithList,
				RulesetID:       "shared-set",
				PredefinedLists: rule.PredefinedLists{"shells": {"sh"}},
				RulesetRevision: "rev-project",
			}},
		},
	}

	got := NewEvaluationState(scopeResolvedRules(host), scopeResolvedRules(project))
	if gotRules := len(got.RulesByType[jobevent.ProcessExec]); gotRules != 2 {
		t.Fatalf("rule count: got %d, want 2", gotRules)
	}
}

func TestNewEvaluationState_DifferentResolvedMaxAlertsKeepSeparateEntries(t *testing.T) {
	t.Parallel()

	host := &jobscope.JobScopeState{
		ResolvedRules: rule.ResolvedRules{
			Rules: []rule.ResolvedRule{{
				CanonicalRuleID: "shared-set/r1",
				Rule: rule.Rule{
					RuleID:    "r1",
					EventType: jobevent.ProcessExec,
					Condition: `process.exec_path.endsWith("/bash")`,
					Action:    rule.RuleActionDetect,
					MaxAlerts: 2,
				},
				RulesetID: "shared-set",
			}},
		},
	}
	project := &jobscope.JobScopeState{
		ResolvedRules: rule.ResolvedRules{
			Rules: []rule.ResolvedRule{{
				CanonicalRuleID: "shared-set/r1",
				Rule: rule.Rule{
					RuleID:    "r1",
					EventType: jobevent.ProcessExec,
					Condition: `process.exec_path.endsWith("/bash")`,
					Action:    rule.RuleActionDetect,
					MaxAlerts: 5,
				},
				RulesetID: "shared-set",
			}},
		},
	}

	got := NewEvaluationState(scopeResolvedRules(host), scopeResolvedRules(project))
	rules := got.RulesByType[jobevent.ProcessExec]
	if len(rules) != 2 {
		t.Fatalf("rule count: got %d, want 2", len(rules))
	}
	var sawHost, sawProject bool
	for _, compiled := range rules {
		switch {
		case compiled.MaxAlerts == 2 && compiled.FeedHost && !compiled.FeedProject:
			sawHost = true
		case compiled.MaxAlerts == 5 && !compiled.FeedHost && compiled.FeedProject:
			sawProject = true
		}
	}
	if !sawHost || !sawProject {
		t.Fatalf("compiled rules: got %#v", rules)
	}
}

func TestNewEvaluationState_DifferentExceptionClausesKeepSeparateEntries(t *testing.T) {
	t.Parallel()

	baseRule := rule.Rule{
		RuleID:    "r1",
		Condition: `process.exec_path.endsWith("/bash")`,
		EventType: jobevent.ProcessExec,
		Action:    rule.RuleActionDetect,
	}
	hostRule := baseRule
	hostRule.Exceptions = `process.exec_path.endsWith("/safe-host")`
	projectRule := baseRule
	projectRule.Exceptions = `process.exec_path.endsWith("/safe-project")`

	host := &jobscope.JobScopeState{
		ResolvedRules: resolvedRules("shared-set", hostRule),
	}
	project := &jobscope.JobScopeState{
		ResolvedRules: resolvedRules("shared-set", projectRule),
	}

	got := NewEvaluationState(scopeResolvedRules(host), scopeResolvedRules(project))
	rules := got.RulesByType[jobevent.ProcessExec]
	if len(rules) != 2 {
		t.Fatalf("rule count: got %d, want 2", len(rules))
	}
	var sawHost, sawProject bool
	for _, compiled := range rules {
		switch {
		case compiled.FeedHost && !compiled.FeedProject:
			sawHost = true
		case !compiled.FeedHost && compiled.FeedProject:
			sawProject = true
		}
	}
	if !sawHost || !sawProject {
		t.Fatalf("compiled rules: got %#v", rules)
	}
}

func TestNewEvaluationState_CorrelationSameContentDedupesAndUnionsScopes(t *testing.T) {
	t.Parallel()

	rules := []rule.Rule{
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
			MaxAlerts: 2,
		},
	}
	hostScope := newCorrelationScope("shared-set", rules)
	projectScope := newProjectScopeWithRules("shared-set", rules)

	got := NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(projectScope))
	if len(got.Correlations) != 1 {
		t.Fatalf("compiled correlations: got %d, want 1", len(got.Correlations))
	}
	compiled := got.Correlations[0]
	if compiled.CanonicalRuleID != "shared-set/corr" {
		t.Fatalf("canonical rule ID: got %q, want %q", compiled.CanonicalRuleID, "shared-set/corr")
	}
	if !compiled.FeedHost || !compiled.FeedProject {
		t.Fatalf("scope routing: got host=%v project=%v, want both true", compiled.FeedHost, compiled.FeedProject)
	}
	if compiled.MaxAlerts != 2 {
		t.Fatalf("max alerts: got %d, want 2", compiled.MaxAlerts)
	}
}

func TestNewEvaluationState_CorrelationDifferentContentKeepsScopeVariants(t *testing.T) {
	t.Parallel()

	baseRule := rule.Rule{
		RuleID:    "single",
		EventType: jobevent.NetworkConnect,
		Condition: `remote_ip == "example.com"`,
		Action:    rule.RuleActionDetect,
	}
	hostScope := newCorrelationScope("shared-set", []rule.Rule{
		baseRule,
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 1`,
			Action:    rule.RuleActionTerminate,
			MaxAlerts: 2,
		},
	})
	projectScope := newProjectScopeWithRules("shared-set", []rule.Rule{
		baseRule,
		{
			RuleID:    "corr",
			Type:      "correlation",
			Condition: `rule["single"].total_count >= 2`,
			Action:    rule.RuleActionTerminate,
			MaxAlerts: 5,
		},
	})

	got := NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(projectScope))
	if len(got.Correlations) != 2 {
		t.Fatalf("compiled correlations: got %d, want 2", len(got.Correlations))
	}

	var sawHost, sawProject bool
	for _, compiled := range got.Correlations {
		if compiled.CanonicalRuleID != "shared-set/corr" {
			t.Fatalf("canonical rule ID: got %q, want %q", compiled.CanonicalRuleID, "shared-set/corr")
		}
		switch {
		case compiled.MaxAlerts == 2 && compiled.FeedHost && !compiled.FeedProject:
			sawHost = true
		case compiled.MaxAlerts == 5 && !compiled.FeedHost && compiled.FeedProject:
			sawProject = true
		}
	}
	if !sawHost || !sawProject {
		t.Fatalf("compiled correlations: got %#v", got.Correlations)
	}
}
