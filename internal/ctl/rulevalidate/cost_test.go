package rulevalidate

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
)

func TestRuleSetCostsWarningPolicy(t *testing.T) {
	t.Parallel()

	env, err := celengine.NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	tests := []struct {
		name         string
		set          rule.RuleSet
		wantWarnings map[string]bool
		wantMissing  []string
	}{
		{
			name: "simple_suffix_match_is_cheap",
			set: ruleSetWithRule(rule.Rule{
				RuleID:    "simple",
				EventKind: jobevent.ProcessExec,
				Condition: `process.exec_path.endsWith("/bash")`,
			}),
			wantWarnings: map[string]bool{"condition": false},
		},
		{
			name: "single_argv_scan_is_acceptable",
			set: ruleSetWithRule(rule.Rule{
				RuleID:    "argv_scan",
				EventKind: jobevent.ProcessExec,
				Condition: `process.argv.exists(a, a.contains("password"))`,
			}),
			wantWarnings: map[string]bool{"condition": false},
		},
		{
			name: "single_list_scan_is_acceptable",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Lists: map[string][]string{
					"bins": {"/bash", "/sh"},
				},
				Rules: []rule.Rule{{
					RuleID:    "list_scan",
					EventKind: jobevent.ProcessExec,
					Condition: `list.bins.exists(b, process.exec_path.endsWith(b))`,
					Action:    rule.RuleActionDetect,
				}},
			},
			wantWarnings: map[string]bool{"condition": false},
		},
		{
			name: "ancestor_times_list_scan_is_acceptable",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Lists: map[string][]string{
					"pkg_install_basenames": {"/npm", "/yarn", "/pnpm", "/pip", "/cargo"},
				},
				Rules: []rule.Rule{{
					RuleID:    "ancestor_list",
					EventKind: jobevent.ProcessExec,
					Condition: `process.ancestors.exists(a, list.pkg_install_basenames.exists(b, a.exec_path.endsWith(b)))`,
					Action:    rule.RuleActionDetect,
				}},
			},
			wantWarnings: map[string]bool{"condition": false},
		},
		{
			// list.X.exists(p, T.contains(p)) is specialized to a Go-side
			// any-match call at parse time, so cel-go scores the rule as
			// cheap even when wrapped in an outer scan.
			name: "argv_times_list_scan_is_specialized_to_cheap",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Lists: map[string][]string{
					"needles": {"password", "token", "secret"},
				},
				Rules: []rule.Rule{{
					RuleID:    "argv_x_list",
					EventKind: jobevent.ProcessExec,
					Condition: `process.argv.exists(a, list.needles.exists(s, a.contains(s)))`,
					Action:    rule.RuleActionDetect,
				}},
			},
			wantWarnings: map[string]bool{"condition": false},
		},
		{
			name: "ancestor_times_argv_scan_warns",
			set: ruleSetWithRule(rule.Rule{
				RuleID:    "ancestor_argv",
				EventKind: jobevent.ProcessExec,
				Condition: `process.ancestors.exists(p, p.argv.exists(a, a.contains("token")))`,
			}),
			wantWarnings: map[string]bool{"condition": true},
		},
		{
			// Exception uses a non-specializable nested scan (literal
			// substring), so the warning fires even though the condition
			// is cheap.
			name: "heavy_exception_warns_even_when_condition_is_cheap",
			set: ruleSetWithRule(rule.Rule{
				RuleID:     "heavy_exception",
				EventKind:  jobevent.ProcessExec,
				Condition:  `process.exec_path.endsWith("/bash")`,
				Exceptions: `process.ancestors.exists(p, p.argv.exists(a, a.contains("token")))`,
			}),
			wantWarnings: map[string]bool{
				"condition": false,
				"exception": true,
			},
		},
		{
			name: "correlation_rules_are_not_event_costed",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{{
					RuleID:    "correlation",
					Type:      "correlation",
					Condition: `rule.foo.total_count >= 1`,
					Action:    rule.RuleActionDetect,
				}},
			},
			wantMissing: []string{"condition"},
		},
		{
			name: "invalid_cel_is_reported_by_compile_not_cost",
			set: ruleSetWithRule(rule.Rule{
				RuleID:    "invalid",
				EventKind: jobevent.ProcessExec,
				Condition: `process.argv[0] == "bash"`,
			}),
			wantMissing: []string{"condition"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			costs := RuleSetCosts(env, tt.set)
			identity := ruleIdentityForFirstRule(tt.set)
			for kind, wantWarning := range tt.wantWarnings {
				got, found := costs[RuleCostKey{Identity: identity, Kind: kind}]
				if !found {
					t.Fatalf("%s cost entry missing; got %v", kind, costs)
				}
				gotWarning := got > CostWarnThreshold
				if gotWarning != wantWarning {
					t.Fatalf("%s warning = %v (cost=%d threshold=%d), want %v", kind, gotWarning, got, CostWarnThreshold, wantWarning)
				}
			}
			for _, kind := range tt.wantMissing {
				if got, found := costs[RuleCostKey{Identity: identity, Kind: kind}]; found {
					t.Fatalf("%s cost entry = %d, want missing; all costs=%v", kind, got, costs)
				}
			}
		})
	}
}

func ruleSetWithRule(r rule.Rule) rule.RuleSet {
	if r.Action == "" {
		r.Action = rule.RuleActionDetect
	}
	return rule.RuleSet{
		RulesetID: "set-1",
		Rules:     []rule.Rule{r},
	}
}

func ruleIdentityForFirstRule(set rule.RuleSet) rule.RuleIdentity {
	if len(set.Rules) == 0 {
		return rule.RuleIdentity{RulesetID: set.RulesetID}
	}
	return rule.RuleIdentity{RulesetID: set.RulesetID, RuleID: set.Rules[0].RuleID}
}
