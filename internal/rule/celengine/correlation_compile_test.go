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
						EventType: jobevent.NetworkConnect,
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
						EventType: jobevent.NetworkConnect,
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
						EventType: jobevent.NetworkConnect,
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
						EventType: jobevent.NetworkConnect,
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
						EventType: jobevent.NetworkConnect,
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
						EventType: jobevent.NetworkConnect,
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
						EventType: jobevent.NetworkConnect,
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
						EventType: jobevent.NetworkConnect,
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
				EventType: jobevent.ProcessExec,
				Condition: `process.exec_path.endsWith("/curl")`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "credential_file_open",
				EventType: jobevent.FileOpen,
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

func TestCompileCorrelationAllowsPresenceBitSum(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	set := rule.RuleSet{
		RulesetID: "set-1",
		Rules: []rule.Rule{
			{
				RuleID:    "a",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "a.example.com"`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "b",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "b.example.com"`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "c",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "c.example.com"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}
	candidate := rule.Rule{
		RuleID: "presence_sum",
		Type:   "correlation",
		Condition: `(
			(rule.a.total_count >= 1 ? 1 : 0) +
			(rule.b.total_count >= 1 ? 1 : 0) +
			(rule.c.total_count >= 1 ? 1 : 0)
		) >= 2`,
		Action: rule.RuleActionDetect,
	}
	set.Rules = append(set.Rules, candidate)
	available := availableRuleCanonicalsForTest(set.RulesetID, set.Rules)

	compiled, err := env.CompileCorrelation(set.RulesetID, candidate, available)
	if err != nil {
		t.Fatalf("compile presence-bit sum: %v", err)
	}

	cases := []struct {
		name   string
		counts map[string]int64
		want   bool
	}{
		{"all_zero", map[string]int64{"set-1/a": 0, "set-1/b": 0, "set-1/c": 0}, false},
		{"single_category_many_hits", map[string]int64{"set-1/a": 3, "set-1/b": 0, "set-1/c": 0}, false},
		{"two_categories", map[string]int64{"set-1/a": 3, "set-1/b": 1, "set-1/c": 0}, true},
		{"three_categories_high_counts", map[string]int64{"set-1/a": 10, "set-1/b": 2, "set-1/c": 7}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := compiled.CompiledCondition.EvalActivation(correlationTestActivation(t, tc.counts))
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if got != tc.want {
				t.Fatalf("eval %v: got %v, want %v", tc.counts, got, tc.want)
			}
		})
	}
}

// TestCompileCorrelationAllowsSubtraction covers the scoring use case where
// authors subtract a noise rule's presence bit from positive signal bits so a
// noisy rule firing alone does not push the correlation over its threshold.
func TestCompileCorrelationAllowsSubtraction(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	set := rule.RuleSet{
		RulesetID: "set-1",
		Rules: []rule.Rule{
			{
				RuleID:    "a",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "a.example.com"`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "b",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "b.example.com"`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "noise",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "noise.example.com"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}
	candidate := rule.Rule{
		RuleID: "scored",
		Type:   "correlation",
		Condition: `(
			(rule.a.total_count >= 1 ? 1 : 0) +
			(rule.b.total_count >= 1 ? 1 : 0) -
			(rule.noise.total_count >= 1 ? 1 : 0)
		) >= 1`,
		Action: rule.RuleActionDetect,
	}
	set.Rules = append(set.Rules, candidate)
	available := availableRuleCanonicalsForTest(set.RulesetID, set.Rules)

	compiled, err := env.CompileCorrelation(set.RulesetID, candidate, available)
	if err != nil {
		t.Fatalf("compile scoring formula with subtraction: %v", err)
	}

	cases := []struct {
		name   string
		counts map[string]int64
		want   bool
	}{
		{"noise_only_does_not_fire", map[string]int64{"set-1/a": 0, "set-1/b": 0, "set-1/noise": 1}, false},
		{"one_signal_no_noise_fires", map[string]int64{"set-1/a": 1, "set-1/b": 0, "set-1/noise": 0}, true},
		{"noise_cancels_one_signal", map[string]int64{"set-1/a": 1, "set-1/b": 0, "set-1/noise": 1}, false},
		{"two_signals_minus_noise_still_fires", map[string]int64{"set-1/a": 1, "set-1/b": 1, "set-1/noise": 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := compiled.CompiledCondition.EvalActivation(correlationTestActivation(t, tc.counts))
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if got != tc.want {
				t.Fatalf("eval %v: got %v, want %v", tc.counts, got, tc.want)
			}
		})
	}
}

// TestCompileCorrelationAllowsNegate locks current behaviour: cel-go's unary
// negate (`-x`) is a distinct operator from binary subtract and was never on
// the deny list, so it remains accepted independently of the Subtract change.
func TestCompileCorrelationAllowsNegate(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	set := rule.RuleSet{
		RulesetID: "set-1",
		Rules: []rule.Rule{
			{
				RuleID:    "a",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "a.example.com"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}
	candidate := rule.Rule{
		RuleID:    "negated",
		Type:      "correlation",
		Condition: `-rule.a.total_count <= 0`,
		Action:    rule.RuleActionDetect,
	}
	set.Rules = append(set.Rules, candidate)
	available := availableRuleCanonicalsForTest(set.RulesetID, set.Rules)

	if _, err := env.CompileCorrelation(set.RulesetID, candidate, available); err != nil {
		t.Fatalf("compile negate: %v", err)
	}
}

func TestCompileCorrelationRejectsDisallowedArithmetic(t *testing.T) {
	t.Parallel()

	env, err := NewEnv()
	if err != nil {
		t.Fatalf("new env: %v", err)
	}

	set := rule.RuleSet{
		RulesetID: "set-1",
		Rules: []rule.Rule{
			{
				RuleID:    "a",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "a.example.com"`,
				Action:    rule.RuleActionDetect,
			},
			{
				RuleID:    "b",
				EventType: jobevent.NetworkConnect,
				Condition: `remote_ip == "b.example.com"`,
				Action:    rule.RuleActionDetect,
			},
		},
	}

	tests := []struct {
		name      string
		condition string
	}{
		{name: "multiply", condition: `rule.a.total_count * 2 >= 1`},
		{name: "divide", condition: `rule.a.total_count / 2 >= 1`},
		{name: "modulo", condition: `rule.a.total_count % 2 >= 1`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			candidate := rule.Rule{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: tt.condition,
				Action:    rule.RuleActionDetect,
			}
			rules := append([]rule.Rule{}, set.Rules...)
			rules = append(rules, candidate)
			available := availableRuleCanonicalsForTest(set.RulesetID, rules)
			if _, err := env.CompileCorrelation(set.RulesetID, candidate, available); err == nil {
				t.Fatalf("expected compile error for %s", tt.name)
			}
		})
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
