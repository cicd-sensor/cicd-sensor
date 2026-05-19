package celengine

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/google/cel-go/cel"
)

func TestCompileCorrelationRejectsInvalidReferences(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	tests := []struct {
		name      string
		set       rule.RuleSet
		candidate rule.Rule
	}{
		{
			name: "missing_rule_id_bracket",
			set: rule.RuleSet{
				RulesetID: "set-1",
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule["missing"].total_count >= 1`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "missing_rule_id_dot",
			set: rule.RuleSet{
				RulesetID: "set-1",
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule.missing.total_count >= 1`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "correlation_to_correlation",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{
					{
						RuleID:    "single",
						EventKind: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionDetect,
					},
					{
						RuleID:    "base",
						Type:      "correlation",
						Condition: `rule["single"].total_count >= 1`,
						Action:    rule.RuleActionDetect,
					},
				},
			},
			candidate: rule.Rule{
				RuleID:    "wrapper",
				Type:      "correlation",
				Condition: `rule["base"].total_count >= 1`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "event_variable_reference",
			set: rule.RuleSet{
				RulesetID: "set-1",
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `process.exec_path == "/bin/curl"`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "predefined_list_reference",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{
					{
						RuleID:    "single",
						EventKind: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionDetect,
					},
				},
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule.single.total_count >= 1 && "prod" in list.projects`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "non_string_literal_index",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{
					{
						RuleID:    "single",
						EventKind: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionDetect,
					},
				},
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule[1].total_count >= 1`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "empty_string_literal_index",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{
					{
						RuleID:    "single",
						EventKind: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionDetect,
					},
				},
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule[""].total_count >= 1`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "dynamic_index",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{
					{
						RuleID:    "single",
						EventKind: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionDetect,
					},
				},
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule[rule_id].total_count >= 1`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "exists_macro_forbidden",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{
					{
						RuleID:    "single",
						EventKind: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionDetect,
					},
				},
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule.exists(r, r.total_count >= 1)`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "no_rule_references",
			set: rule.RuleSet{
				RulesetID: "set-1",
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `true`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			name: "cross_set_reference",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{
					{
						RuleID:    "single",
						EventKind: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionDetect,
					},
				},
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule["other-set/single"].total_count >= 1`,
				Action:    rule.RuleActionDetect,
			},
		},
		{
			// Inner-key access outside the whitelist (only `total_count`)
			// must be rejected at compile time even though the CEL type system
			// alone would accept any string key on the nested map.
			name: "disallowed_inner_field",
			set: rule.RuleSet{
				RulesetID: "set-1",
				Rules: []rule.Rule{
					{
						RuleID:    "single",
						EventKind: jobevent.NetworkConnect,
						Condition: `remote_ip == "example.com"`,
						Action:    rule.RuleActionDetect,
					},
				},
			},
			candidate: rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule["single"].first_hit_at >= 1`,
				Action:    rule.RuleActionDetect,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			set := tt.set
			set.Rules = append(set.Rules, tt.candidate)
			available := availableRuleCanonicalsForTest(set.RulesetID, set.Rules)
			if _, err := env.CompileCorrelation(set.RulesetID, tt.candidate, available); err == nil {
				t.Fatal("expected compile error")
			}
		})
	}
}

func TestCompileCorrelationCanonicalizesDotAndBracketReferences(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	set := rule.RuleSet{
		RulesetID: "set-1",
		Rules: []rule.Rule{
			{
				RuleID:    "suspicious_bin_exec",
				EventKind: jobevent.ProcessExec,
				Condition: `process.exec_path.endsWith("/curl")`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "credential_file_open",
				EventKind: jobevent.FileOpen,
				Condition: `path.endsWith(".env")`,
				Action:    rule.RuleActionDetect,
			},
		},
	}

	candidate := rule.Rule{
		RuleID:    "corr",
		Type:      "correlation",
		Condition: `rule.credential_file_open.total_count >= 1 && rule["suspicious_bin_exec"].total_count >= 1`,
		Action:    rule.RuleActionTerminate,
	}
	set.Rules = append(set.Rules, candidate)
	available := availableRuleCanonicalsForTest(set.RulesetID, set.Rules)

	compiled, err := env.CompileCorrelation(set.RulesetID, candidate, available)
	if err != nil {
		t.Fatalf("compile correlation: %v", err)
	}

	if compiled.CanonicalRuleID != "set-1/corr" {
		t.Fatalf("canonical rule ID: got %q, want %q", compiled.CanonicalRuleID, "set-1/corr")
	}
	matched, err := compiled.CompiledCondition.EvalActivation(correlationTestActivation(t, map[string]int64{
		"set-1/credential_file_open": 1,
		"set-1/suspicious_bin_exec":  1,
	}))
	if err != nil {
		t.Fatalf("eval canonicalized correlation: %v", err)
	}
	if !matched {
		t.Fatal("expected canonicalized correlation to match canonical activation keys")
	}
}

func TestCompileCorrelationKeepsRuleIDCase(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	available := map[string]rule.CanonicalRuleID{
		"RuleA": "set-1/RuleA",
	}
	candidate := rule.Rule{
		RuleID:    "corr",
		Type:      "correlation",
		Condition: `rule["RuleA"].total_count >= 1`,
		Action:    rule.RuleActionDetect,
	}

	compiled, err := env.CompileCorrelation("set-1", candidate, available)
	if err != nil {
		t.Fatalf("compile correlation: %v", err)
	}

	if compiled.CanonicalRuleID != "set-1/corr" {
		t.Fatalf("canonical rule ID: got %q, want %q", compiled.CanonicalRuleID, "set-1/corr")
	}
	matched, err := compiled.CompiledCondition.EvalActivation(correlationTestActivation(t, map[string]int64{
		"set-1/RuleA": 1,
	}))
	if err != nil {
		t.Fatalf("eval case-sensitive correlation: %v", err)
	}
	if !matched {
		t.Fatal("expected case-sensitive rule id to match canonical activation key")
	}
}

func correlationTestActivation(t *testing.T, counts map[string]int64) cel.Activation {
	t.Helper()

	rules := make(map[string]any, len(counts))
	for canonical, total := range counts {
		rules[canonical] = newCELRuleHitVal(CELRuleHit{TotalCount: total})
	}
	activation, err := cel.NewActivation(map[string]any{"rule": rules})
	if err != nil {
		t.Fatalf("new correlation test activation: %v", err)
	}
	return activation
}

func availableRuleCanonicalsForTest(setIdentity string, rules []rule.Rule) map[string]rule.CanonicalRuleID {
	out := make(map[string]rule.CanonicalRuleID)
	for _, candidate := range rules {
		if candidate.Type == "correlation" {
			continue
		}
		out[candidate.RuleID] = rule.RuleIdentity{
			RulesetID: setIdentity,
			RuleID:    candidate.RuleID,
		}.CanonicalRuleID()
	}
	return out
}
