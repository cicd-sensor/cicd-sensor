package evaluation

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestNewEvaluationState_CorrelationCompileFailuresBecomeWarnings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		rules            []rule.Rule
		modifiers        []rule.RuleModifier
		wantCorrelations int
		wantWarnings     int
	}{
		{
			name: "missing_rule_id_reference",
			rules: []rule.Rule{{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `rule["missing"].total_count >= 1`,
				Action:    rule.RuleActionDetect,
			}},
			wantWarnings: 1,
		},
		{
			name: "correlation_to_correlation_reference",
			rules: []rule.Rule{
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
				{
					RuleID:    "wrapper",
					Type:      "correlation",
					Condition: `rule["base"].total_count >= 1`,
					Action:    rule.RuleActionDetect,
				},
			},
			wantCorrelations: 1,
			wantWarnings:     1,
		},
		{
			name: "event_variable_reference",
			rules: []rule.Rule{{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `process.exec_path.endsWith("/curl")`,
				Action:    rule.RuleActionDetect,
			}},
			wantWarnings: 1,
		},
		{
			name: "cross_set_reference",
			rules: []rule.Rule{
				{
					RuleID:    "single",
					EventType: jobevent.NetworkConnect,
					Condition: `remote_ip == "example.com"`,
					Action:    rule.RuleActionDetect,
				},
				{
					RuleID:    "corr",
					Type:      "correlation",
					Condition: `rule["other-set/single"].total_count >= 1`,
					Action:    rule.RuleActionDetect,
				},
			},
			wantWarnings: 1,
		},
		{
			name: "missing_referenced_rules",
			rules: []rule.Rule{{
				RuleID:    "corr",
				Type:      "correlation",
				Condition: `true`,
				Action:    rule.RuleActionDetect,
			}},
			wantWarnings: 1,
		},
		{
			name: "disabled_rule_reference",
			rules: []rule.Rule{
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
					Action:    rule.RuleActionDetect,
				},
			},
			modifiers: []rule.RuleModifier{{
				ModifierID: "disable-single",
				Targets: []rule.RuleModifierTarget{{
					RulesetID: "host-set",
					RuleID:    "single",
				}},
				Disable: boolPtr(true),
			}},
			wantWarnings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hostScope := newCorrelationScope("host-set", tt.rules)
			hostScope.RuleModifiers = tt.modifiers
			hostScope.ResolveRules(jobcontext.JobIdentity{})
			eval := NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))

			if got := len(eval.Correlations); got != tt.wantCorrelations {
				t.Fatalf("compiled correlations: got %d, want %d", got, tt.wantCorrelations)
			}
			if got := len(hostScope.ResolvedRules.Warnings); got != tt.wantWarnings {
				t.Fatalf("warnings: got %d, want %d", got, tt.wantWarnings)
			}
			if tt.wantWarnings > 0 {
				warning := hostScope.ResolvedRules.Warnings[0]
				if warning.Kind != "compile_error" {
					t.Fatalf("warning type: got %q, want %q", warning.Kind, "compile_error")
				}
			}
		})
	}
}

func TestNewEvaluationState_InvalidAddedExceptionSkipsRule(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:    "single",
			EventType: jobevent.NetworkConnect,
			Condition: `remote_ip == "example.com"`,
			Action:    rule.RuleActionDetect,
		}},
	}}
	hostScope.RuleModifiers = []rule.RuleModifier{{
		ModifierID:    "local/bad-exception",
		Targets:       []rule.RuleModifierTarget{{RulesetID: "host-set", RuleID: "single"}},
		AddExceptions: `remote_ip.matches(".*")`,
	}}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	got := NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	if got == nil {
		t.Fatal("expected evaluation state")
	}

	totalRules := 0
	for _, rules := range got.RulesByType {
		totalRules += len(rules)
	}
	if totalRules != 0 {
		t.Fatalf("compiled rule count: got %d, want 0", totalRules)
	}
	if len(hostScope.ResolvedRules.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(hostScope.ResolvedRules.Warnings))
	}
	if hostScope.ResolvedRules.Warnings[0].Kind != "compile_error" {
		t.Fatalf("warning type: got %q, want %q", hostScope.ResolvedRules.Warnings[0].Kind, "compile_error")
	}
}

func TestNewEvaluationState_CompilesBaseAndAddedExceptionsSeparately(t *testing.T) {
	t.Parallel()

	hostScope := jobscope.NewHost()
	hostScope.RuleSets = []rule.RuleSet{{
		RulesetID: "host-set",
		Rules: []rule.Rule{{
			RuleID:     "single",
			EventType:  jobevent.NetworkConnect,
			Condition:  `remote_ip == "example.com"`,
			Exceptions: `protocol == "tcp"`,
			Action:     rule.RuleActionDetect,
		}},
	}}
	hostScope.RuleModifiers = []rule.RuleModifier{
		{
			ModifierID:    "local/first",
			Targets:       []rule.RuleModifierTarget{{RulesetID: "host-set", RuleID: "single"}},
			AddExceptions: `remote_ip == "safe.example.com"`,
		},
		{
			ModifierID:    "local/second",
			Targets:       []rule.RuleModifierTarget{{RulesetID: "host-set", RuleID: "single"}},
			AddExceptions: `protocol == "udp"`,
		},
	}
	hostScope.ResolveRules(jobcontext.JobIdentity{})

	got := NewEvaluationState(scopeResolvedRules(hostScope), scopeResolvedRules(nil))
	compiled := got.RulesByType[jobevent.NetworkConnect]
	if len(compiled) != 1 {
		t.Fatalf("compiled rule count: got %d, want 1", len(compiled))
	}
	if len(compiled[0].Exceptions) != 3 {
		t.Fatalf("compiled exception count: got %d, want 3", len(compiled[0].Exceptions))
	}
	if compiled[0].Exceptions[0].ModifierIdentity != "" {
		t.Fatalf("base exception modifier identity: got %q, want empty", compiled[0].Exceptions[0].ModifierIdentity)
	}
	if compiled[0].Exceptions[1].ModifierIdentity != "local/first" {
		t.Fatalf("first modifier identity: got %q, want %q", compiled[0].Exceptions[1].ModifierIdentity, "local/first")
	}
	if compiled[0].Exceptions[2].ModifierIdentity != "local/second" {
		t.Fatalf("second modifier identity: got %q, want %q", compiled[0].Exceptions[2].ModifierIdentity, "local/second")
	}
	if compiled[0].StaticActivation == nil {
		t.Fatal("expected static activation")
	}
}
