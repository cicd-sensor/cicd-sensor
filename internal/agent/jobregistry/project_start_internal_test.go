package jobregistry

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestBuildProjectScopeFromLocalConfigCanAddBaselineFallback(t *testing.T) {
	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")
	jr.SetBaselineLoadForTesting(func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		return rulesource.LoadedRules{RuleSets: []rule.RuleSet{{
			RulesetID: "baseline",
			Rules: []rule.Rule{{
				RuleID:    "baseline_exec",
				EventType: jobevent.ProcessExec,
				Condition: `process_name == "bash"`,
				Action:    rule.RuleActionDetect,
			}},
		}}}, nil
	})

	scope, err := jr.buildProjectScopeFromLocalConfig(testCtx, id, 7, []rulesource.LoadedRules{{
		RuleSets: []rule.RuleSet{{
			RulesetID: "project",
			Rules: []rule.Rule{{
				RuleID:    "project_exec",
				EventType: jobevent.ProcessExec,
				Condition: `process_name == "go"`,
				Action:    rule.RuleActionDetect,
			}},
		}},
	}})
	if err != nil {
		t.Fatalf("buildProjectScopeFromLocalConfig: %v", err)
	}
	if got := len(scope.RuleSets); got != 2 {
		t.Fatalf("rule_sets: got %d, want 2", got)
	}
	if got := scope.DefaultMaxAlertsPerRule; got != 7 {
		t.Fatalf("default_max_alerts_per_rule: got %d, want 7", got)
	}
	if got := len(scope.ResolvedRules.Rules); got != 2 {
		t.Fatalf("resolved rules: got %d, want 2", got)
	}
}

func TestBuildProjectScopeFromLocalConfigKeepsBaselineFirst(t *testing.T) {
	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")
	jr.SetBaselineLoadForTesting(func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		return rulesource.LoadedRules{RuleSets: []rule.RuleSet{{
			RulesetID: "shared",
			Rules: []rule.Rule{{
				RuleID:    "duplicate",
				EventType: jobevent.ProcessExec,
				Condition: `process_name == "baseline"`,
				Action:    rule.RuleActionDetect,
			}},
		}}}, nil
	})

	scope, err := jr.buildProjectScopeFromLocalConfig(testCtx, id, 0, []rulesource.LoadedRules{{
		RuleSets: []rule.RuleSet{{
			RulesetID: "shared",
			Rules: []rule.Rule{{
				RuleID:    "duplicate",
				EventType: jobevent.ProcessExec,
				Condition: `process_name == "project"`,
				Action:    rule.RuleActionDetect,
			}},
		}},
	}})
	if err != nil {
		t.Fatalf("buildProjectScopeFromLocalConfig: %v", err)
	}
	got, ok := scope.ResolvedRules.Lookup(rule.RuleIdentity{RulesetID: "shared", RuleID: "duplicate"})
	if !ok {
		t.Fatal("duplicate rule was not resolved")
	}
	if got.Rule.Condition != `process_name == "baseline"` {
		t.Fatalf("condition: got %q, want baseline rule", got.Rule.Condition)
	}
}

func TestBuildProjectScopeFromManagerConfigSkipsLocalAndBaseline(t *testing.T) {
	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")
	meta := jobcontext.JobMetadata{}
	jr.SetBaselineLoadForTesting(func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		t.Fatal("baseline loader should not be called in project manager mode")
		return rulesource.LoadedRules{}, nil
	})

	scope, err := jr.buildProjectScopeFromManagerConfig(testCtx, id, meta, "machine", managerclient.Connection{}, fakeManagerFetcher{})
	if err != nil {
		t.Fatalf("buildProjectScopeFromManagerConfig: %v", err)
	}
	if got := len(scope.RuleSets); got != 0 {
		t.Fatalf("rule_sets: got %d, want 0", got)
	}
	if got := scope.DefaultMaxAlertsPerRule; got != 0 {
		t.Fatalf("default_max_alerts_per_rule: got %d, want 0", got)
	}
}
