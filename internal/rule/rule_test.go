package rule_test

import (
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestValidateRuleSet(t *testing.T) {
	cases := []struct {
		name    string
		set     rule.RuleSet
		wantErr string
	}{
		{
			name: "valid set",
			set: rule.RuleSet{
				RulesetID: "test-set",
				Rules: []rule.Rule{
					{RuleID: "r1", EventType: jobevent.ProcessExec, Condition: `process_name == "bash"`, Action: rule.RuleActionDetect},
				},
			},
		},
		{
			name: "empty rules is valid",
			set:  rule.RuleSet{RulesetID: "s"},
		},
		{name: "missing ruleset_id", set: rule.RuleSet{}, wantErr: "ruleset_id is required"},
		{
			name: "missing rule_id",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules:     []rule.Rule{{EventType: jobevent.FileOpen, Condition: `path.contains(".env")`, Action: rule.RuleActionDetect}},
			},
			wantErr: "rule_id is required",
		},
		{
			name: "missing condition",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules:     []rule.Rule{{RuleID: "r1", EventType: jobevent.FileOpen, Action: rule.RuleActionDetect}},
			},
			wantErr: "condition is required",
		},
		{
			name: "negative max_alerts",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules:     []rule.Rule{{RuleID: "r1", EventType: jobevent.FileOpen, Condition: `path.contains(".env")`, Action: rule.RuleActionDetect, MaxAlerts: -1}},
			},
			wantErr: "max_alerts must be non-negative",
		},
		{
			name: "max_alerts above ceiling is allowed and falls back later",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules:     []rule.Rule{{RuleID: "r1", EventType: jobevent.FileOpen, Condition: `path.contains(".env")`, Action: rule.RuleActionDetect, MaxAlerts: rule.MaxAlertsHardCeiling + 1}},
			},
		},
		{
			name: "missing event_type on single-event rule",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules:     []rule.Rule{{RuleID: "r1", Condition: `process_name == "bash"`, Action: rule.RuleActionDetect}},
			},
			wantErr: "event_type is required",
		},
		{
			name: "correlation rule may omit event_type",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules: []rule.Rule{{
					RuleID:    "corr",
					Type:      "correlation",
					Condition: `rule.base.total_count > 0`,
					Action:    rule.RuleActionDetect,
				}},
			},
		},
		{
			name: "invalid action",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules:     []rule.Rule{{RuleID: "r1", EventType: jobevent.ProcessExec, Condition: `process_name == "bash"`, Action: rule.RuleAction("alert")}},
			},
			wantErr: "action must be detect, terminate, or collect",
		},
		{
			name: "duplicate rule_id",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules: []rule.Rule{
					{RuleID: "r1", EventType: jobevent.ProcessExec, Condition: `process_name == "bash"`, Action: rule.RuleActionDetect},
					{RuleID: "r1", EventType: jobevent.ProcessExec, Condition: `process_name == "curl"`, Action: rule.RuleActionTerminate},
				},
			},
			wantErr: `duplicate rule_id "r1"`,
		},
		{
			name: "target include matcher must not be empty",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules: []rule.Rule{{
					RuleID:    "r1",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
					Target: rule.RuleTarget{
						Include: []rule.RuleTargetMatcher{{}},
					},
				}},
			},
			wantErr: "target.include[0] must set provider_host or path",
		},
		{
			name: "target include must not be empty list",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules: []rule.Rule{{
					RuleID:    "r1",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
					Target:    rule.RuleTarget{Include: []rule.RuleTargetMatcher{}},
				}},
			},
			wantErr: "target.include must not be an empty list",
		},
		{
			name: "target exclude matcher must not be empty",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules: []rule.Rule{{
					RuleID:    "r1",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
					Target:    rule.RuleTarget{Exclude: []rule.RuleTargetMatcher{{}}},
				}},
			},
			wantErr: "target.exclude[0] must set provider_host or path",
		},
		{
			name: "target exclude must not be empty list",
			set: rule.RuleSet{
				RulesetID: "s",
				Rules: []rule.Rule{{
					RuleID:    "r1",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
					Target:    rule.RuleTarget{Exclude: []rule.RuleTargetMatcher{}},
				}},
			},
			wantErr: "target.exclude must not be an empty list",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rule.ValidateRuleSet(&tc.set)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestIsResolvedRuleContentEqual(t *testing.T) {
	t.Parallel()

	base := rule.ResolvedRule{
		CanonicalRuleID: "set-a/r1",
		RulesetID:       "set-a",
		Rule: rule.Rule{
			RuleID:    "r1",
			EventType: jobevent.ProcessExec,
			Condition: `process_name == "bash"`,
			Action:    rule.RuleActionDetect,
		},
		AppliedModifiers: []string{"mod-1"},
		ExceptionClauses: []rule.ResolvedExceptionClause{{Source: `process_name == "sh"`, ModifierIdentity: "mod-1"}},
		PredefinedLists:  rule.PredefinedLists{"bins": {"/bin/bash"}},
	}

	sameContent := base
	sameContent.CanonicalRuleID = "set-b/r1"
	sameContent.RulesetID = "set-b"
	if !rule.IsResolvedRuleContentEqual(base, sameContent) {
		t.Fatal("identity-only changes should not affect content equality")
	}

	differentException := base
	differentException.ExceptionClauses = []rule.ResolvedExceptionClause{{Source: `process_name == "zsh"`, ModifierIdentity: "mod-1"}}
	if rule.IsResolvedRuleContentEqual(base, differentException) {
		t.Fatal("different exception clauses should affect content equality")
	}
}

func TestResolvedRules_Lookup(t *testing.T) {
	t.Parallel()

	rules := rule.ResolvedRules{
		Rules: []rule.ResolvedRule{
			{
				RulesetID:       "set-a",
				RulesetRevision: "sha256:a",
				Rule:            rule.Rule{RuleID: "one", RuleName: "One"},
			},
			{
				RulesetID:       "set-b",
				RulesetRevision: "sha256:b",
				Rule:            rule.Rule{RuleID: "two", RuleName: "Two"},
			},
		},
	}

	got, found := rules.Lookup(rule.RuleIdentity{RulesetID: "set-b", RuleID: "two"})
	if !found {
		t.Fatal("expected rule to be found")
	}
	if got.Rule.RuleName != "Two" || got.RulesetRevision != "sha256:b" {
		t.Fatalf("lookup result: got %+v", got)
	}

	if _, found := rules.Lookup(rule.RuleIdentity{RulesetID: "set-b", RuleID: "missing"}); found {
		t.Fatal("missing rule should not be found")
	}
}

func TestValidateRuleSet_RejectsInvalidRuleID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		ruleID  string
		wantErr bool
	}{
		{name: "valid_snake_case", ruleID: "suspicious_bin_exec"},
		{name: "valid_single_letter", ruleID: "a"},
		{name: "valid_underscore_start", ruleID: "_internal"},
		{name: "valid_mixed_case", ruleID: "Rule1"},
		{name: "invalid_hyphen", ruleID: "suspicious-bin-exec", wantErr: true},
		{name: "invalid_digit_start", ruleID: "1st", wantErr: true},
		{name: "invalid_space", ruleID: "foo bar", wantErr: true},
		{name: "invalid_empty", ruleID: "", wantErr: true},
		{name: "invalid_unicode", ruleID: "日本語", wantErr: true},
		{name: "invalid_dot", ruleID: "foo.bar", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := rule.RuleSet{
				RulesetID: "test-set",
				Rules: []rule.Rule{{
					RuleID:    tc.ruleID,
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				}},
			}

			err := rule.ValidateRuleSet(&set)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateRuleModifier(t *testing.T) {
	cases := []struct {
		name    string
		mod     rule.RuleModifier
		wantErr string
	}{
		{
			name: "valid modifier",
			mod: rule.RuleModifier{
				ModifierID: "m1",
				Targets:    []rule.RuleModifierTarget{{RulesetID: "s1"}},
			},
		},
		{
			name:    "missing modifier_id",
			mod:     rule.RuleModifier{Targets: []rule.RuleModifierTarget{{RulesetID: "s1"}}},
			wantErr: "modifier_id is required",
		},
		{
			name:    "empty targets",
			mod:     rule.RuleModifier{ModifierID: "m1"},
			wantErr: "at least one target is required",
		},
		{
			name: "target missing ruleset_id",
			mod: rule.RuleModifier{
				ModifierID: "m1",
				Targets:    []rule.RuleModifierTarget{{RuleID: "r1"}},
			},
			wantErr: "ruleset_id is required",
		},
		{
			name: "negative override_max_alerts",
			mod: rule.RuleModifier{
				ModifierID:        "m1",
				Targets:           []rule.RuleModifierTarget{{RulesetID: "s1"}},
				OverrideMaxAlerts: intPtr(-1),
			},
			wantErr: "override_max_alerts must be non-negative",
		},
		{
			name: "zero override_max_alerts rejected",
			mod: rule.RuleModifier{
				ModifierID:        "m1",
				Targets:           []rule.RuleModifierTarget{{RulesetID: "s1"}},
				OverrideMaxAlerts: intPtr(0),
			},
			wantErr: "override_max_alerts: 0 is not allowed",
		},
		{
			name: "override_max_alerts above ceiling",
			mod: rule.RuleModifier{
				ModifierID:        "m1",
				Targets:           []rule.RuleModifierTarget{{RulesetID: "s1"}},
				OverrideMaxAlerts: intPtr(rule.MaxAlertsHardCeiling + 1),
			},
			wantErr: "override_max_alerts must be <=",
		},
		{
			name: "override_action must not be empty",
			mod: rule.RuleModifier{
				ModifierID:     "m1",
				Targets:        []rule.RuleModifierTarget{{RulesetID: "s1"}},
				OverrideAction: func() *rule.RuleAction { v := rule.RuleAction(""); return &v }(),
			},
			wantErr: "override_action must not be empty",
		},
		{
			name: "invalid override_action",
			mod: rule.RuleModifier{
				ModifierID:     "m1",
				Targets:        []rule.RuleModifierTarget{{RulesetID: "s1"}},
				OverrideAction: func() *rule.RuleAction { v := rule.RuleAction("alert"); return &v }(),
			},
			wantErr: "override_action must be detect, terminate, or collect",
		},
		{
			name: "add_target_exclude matcher must not be empty",
			mod: rule.RuleModifier{
				ModifierID:       "m1",
				Targets:          []rule.RuleModifierTarget{{RulesetID: "s1"}},
				AddTargetExclude: []rule.RuleTargetMatcher{{}},
			},
			wantErr: "add_target_exclude[0] must set provider_host or path",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rule.ValidateRuleModifier(&tc.mod)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
