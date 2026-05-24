package jobscope_test

import (
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestJobScopeState_ApplyManagerConfig_AppendsAndResolvesHostScope(t *testing.T) {
	scope := jobscope.NewHost()

	scope.RuleSets = []rule.RuleSet{
		{
			RulesetID: "local-set",
			Rules: []rule.Rule{
				{
					RuleID:    "local-rule",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				},
			},
		},
	}

	cfg := jobscope.ManagerConfig{
		ConfigRevision: "sha256:test",
		RuleSources: []rulesource.LoadedRules{{
			RuleSets: []rule.RuleSet{{
				RulesetID: "manager-set",
				Rules: []rule.Rule{
					{
						RuleID:    "manager-rule",
						EventType: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionTerminate,
					},
				},
			}},
		}},
		OutputSettings: &managerv1.OutputSettings{
			SummaryLog: &managerv1.OutputSetting{Enabled: true},
		},
	}

	if err := scope.ApplyManagerConfig(cfg); err != nil {
		t.Fatalf("ApplyManagerConfig: %v", err)
	}
	scope.ResolveRules(jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"))

	if len(scope.RuleSets) != 2 {
		t.Fatalf("rule_sets: got %d, want 2", len(scope.RuleSets))
	}
	if !scope.OutputSettings.GetSummaryLog().GetEnabled() {
		t.Fatal("expected summary_log output settings to be set")
	}
	if len(scope.ResolvedRules.Rules) != 2 {
		t.Fatalf("resolved rules: got %d, want 2", len(scope.ResolvedRules.Rules))
	}
}

func TestJobScopeState_ApplyManagerConfig_AppliesProjectScope(t *testing.T) {
	scope := jobscope.NewProject()

	if err := scope.ApplyManagerConfig(jobscope.ManagerConfig{
		RuleSources: []rulesource.LoadedRules{{RuleSets: []rule.RuleSet{{RulesetID: "manager-set"}}}},
	}); err != nil {
		t.Fatalf("ApplyManagerConfig: %v", err)
	}
	if len(scope.RuleSets) != 1 {
		t.Fatalf("project scope rule_sets: got %d, want 1", len(scope.RuleSets))
	}
}

func TestJobScopeState_ApplyManagerConfig_NilResultIsNoOp(t *testing.T) {
	t.Parallel()

	scope := jobscope.NewHost()
	scope.RuleSets = []rule.RuleSet{{RulesetID: "local-set"}}

	if err := scope.ApplyManagerConfig(jobscope.ManagerConfig{}); err != nil {
		t.Fatalf("ApplyManagerConfig(empty): %v", err)
	}
	if len(scope.RuleSets) != 1 || scope.RuleSets[0].RulesetID != "local-set" {
		t.Fatalf("rule_sets changed after nil result: %#v", scope.RuleSets)
	}
}

func TestJobScopeState_ApplyManagerConfig_NilScopeErrors(t *testing.T) {
	t.Parallel()

	var scope *jobscope.JobScopeState
	err := scope.ApplyManagerConfig(jobscope.ManagerConfig{})
	if err == nil {
		t.Fatal("ApplyManagerConfig on nil scope: got nil, want error")
	}
	if !strings.Contains(err.Error(), "nil scope") {
		t.Fatalf("ApplyManagerConfig error: got %q, want nil scope", err)
	}
}

func TestJobScopeState_ApplyProjectLocalConfig(t *testing.T) {
	scope := jobscope.NewProject()

	err := scope.ApplyProjectLocalConfig(jobscope.ProjectLocalConfig{
		DefaultMaxAlertsPerRule: 12,
		RuleSources: []rulesource.LoadedRules{{
			RuleSets: []rule.RuleSet{{RulesetID: "project-set"}},
		}},
	})
	if err != nil {
		t.Fatalf("ApplyProjectLocalConfig: %v", err)
	}
	if got := scope.DefaultMaxAlertsPerRule; got != 12 {
		t.Fatalf("default max alerts: got %d, want 12", got)
	}
	if len(scope.RuleSets) != 1 || scope.RuleSets[0].RulesetID != "project-set" {
		t.Fatalf("project rule sets: %#v", scope.RuleSets)
	}
}

func TestJobScopeState_ApplyBaselineRules(t *testing.T) {
	scope := jobscope.NewHost()

	if err := scope.ApplyBaselineRules(rulesource.LoadedRules{
		RuleSets:      []rule.RuleSet{{RulesetID: "baseline-set"}},
		RuleModifiers: []rule.RuleModifier{{ModifierID: "baseline-modifier"}},
	}); err != nil {
		t.Fatalf("ApplyBaselineRules: %v", err)
	}
	if len(scope.RuleSets) != 1 || scope.RuleSets[0].RulesetID != "baseline-set" {
		t.Fatalf("baseline rule sets: %#v", scope.RuleSets)
	}
	if len(scope.RuleModifiers) != 1 || scope.RuleModifiers[0].ModifierID != "baseline-modifier" {
		t.Fatalf("baseline rule modifiers: %#v", scope.RuleModifiers)
	}
}
