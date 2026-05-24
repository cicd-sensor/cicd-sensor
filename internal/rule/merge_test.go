package rule_test

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func testSet(id string, rules ...rule.Rule) rule.RuleSet {
	return rule.RuleSet{
		RulesetID: id,
		Rules:     rules,
	}
}

func testRule(id string, eventType jobevent.Type, action rule.RuleAction) rule.Rule {
	return rule.Rule{
		RuleID:    id,
		EventType: eventType,
		Condition: `process_name == "bash"`,
		Action:    action,
	}
}

func boolPtr(v bool) *bool                         { return &v }
func intPtr(v int) *int                            { return &v }
func actionPtr(v rule.RuleAction) *rule.RuleAction { return &v }

func TestMerge_FlattenSingleSet(t *testing.T) {
	in := rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1",
				testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect),
				testRule("r2", jobevent.NetworkConnect, rule.RuleActionTerminate),
			),
		},
	}
	got := rule.Merge(in)
	if len(got.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(got.Rules))
	}
	if got.Rules[0].CanonicalRuleID != "s1/r1" {
		t.Fatalf("canonical_rule_id[0]: got %q, want %q", got.Rules[0].CanonicalRuleID, "s1/r1")
	}
	if got.Rules[1].CanonicalRuleID != "s1/r2" {
		t.Fatalf("canonical_rule_id[1]: got %q, want %q", got.Rules[1].CanonicalRuleID, "s1/r2")
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("warnings: got %d, want 0", len(got.Warnings))
	}
}

func TestMerge_CanonicalRuleIDCollision_SameContent_SilentDedupe(t *testing.T) {
	r := testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect)
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1", r),
			testSet("s1", r),
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("warnings: got %d, want 0", len(got.Warnings))
	}
}

func TestMerge_CanonicalRuleIDCollision_DifferentContent_WarnsAndKeepsFirst(t *testing.T) {
	r1 := testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect)
	r2 := testRule("r1", jobevent.ProcessExec, rule.RuleActionTerminate)
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1", r1),
			testSet("s1", r2),
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if got.Rules[0].Rule.Action != rule.RuleActionDetect {
		t.Fatalf("kept action: got %q, want first rule action %q", got.Rules[0].Rule.Action, rule.RuleActionDetect)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(got.Warnings))
	}
	if got.Warnings[0].Kind != "duplicate_identity_diff_content" {
		t.Fatalf("warning type: got %q", got.Warnings[0].Kind)
	}
	if got.Warnings[0].Identity != (rule.RuleIdentity{RulesetID: "s1", RuleID: "r1"}) {
		t.Fatalf("warning identity: got %#v", got.Warnings[0].Identity)
	}
}

func TestMerge_ModifierDisable(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1",
				testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect),
				testRule("r2", jobevent.FileOpen, rule.RuleActionDetect),
			),
		},
		RuleModifiers: []rule.RuleModifier{
			{
				ModifierID: "local/disable-r1",
				Targets:    []rule.RuleModifierTarget{{RulesetID: "s1", RuleID: "r1"}},
				Disable:    boolPtr(true),
			},
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if got.Rules[0].Rule.RuleID != "r2" {
		t.Fatalf("remaining rule: got %q, want r2", got.Rules[0].Rule.RuleID)
	}
}

func TestMerge_ModifierOverrideAction(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1",
				testRule("r1", jobevent.ProcessExec, rule.RuleActionTerminate),
			),
		},
		RuleModifiers: []rule.RuleModifier{
			{
				ModifierID:     "local/override-action",
				Targets:        []rule.RuleModifierTarget{{RulesetID: "s1"}},
				OverrideAction: actionPtr(rule.RuleActionDetect),
			},
		},
	})
	if got.Rules[0].Rule.Action != rule.RuleActionDetect {
		t.Fatalf("action: got %q, want %q", got.Rules[0].Rule.Action, rule.RuleActionDetect)
	}
	if len(got.Rules[0].AppliedModifiers) != 1 || got.Rules[0].AppliedModifiers[0] != "local/override-action" {
		t.Fatalf("applied_modifiers: got %v", got.Rules[0].AppliedModifiers)
	}
}

func TestMerge_ModifierCanEscalateAction(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1",
				testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect),
			),
		},
		RuleModifiers: []rule.RuleModifier{
			{
				ModifierID:     "local/escalate",
				Targets:        []rule.RuleModifierTarget{{RulesetID: "s1"}},
				OverrideAction: actionPtr(rule.RuleActionTerminate),
			},
		},
	})
	if got.Rules[0].Rule.Action != rule.RuleActionTerminate {
		t.Fatalf("action: got %q, want %q", got.Rules[0].Rule.Action, rule.RuleActionTerminate)
	}
}

func TestMerge_InvalidEmptyOverrideActionIsSkippedWithWarning(t *testing.T) {
	empty := rule.RuleAction("")
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1",
				testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect),
			),
		},
		RuleModifiers: []rule.RuleModifier{
			{
				ModifierID:     "local/bad-empty-action",
				Targets:        []rule.RuleModifierTarget{{RulesetID: "s1"}},
				OverrideAction: &empty,
			},
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if got.Rules[0].Rule.Action != rule.RuleActionDetect {
		t.Fatalf("action: got %q, want %q", got.Rules[0].Rule.Action, rule.RuleActionDetect)
	}
	if len(got.Rules[0].AppliedModifiers) != 0 {
		t.Fatalf("applied_modifiers: got %v, want none", got.Rules[0].AppliedModifiers)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(got.Warnings))
	}
	if got.Warnings[0].Kind != "invalid_modifier_skipped" {
		t.Fatalf("warning type: got %q, want %q", got.Warnings[0].Kind, "invalid_modifier_skipped")
	}
}

func TestMerge_InvalidModifierIsSkippedWithWarning(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1",
				testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect),
			),
		},
		RuleModifiers: []rule.RuleModifier{
			{
				ModifierID:        "local/bad-max-alerts",
				Targets:           []rule.RuleModifierTarget{{RulesetID: "s1", RuleID: "r1"}},
				OverrideMaxAlerts: intPtr(0),
			},
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if got.Rules[0].Rule.Action != rule.RuleActionDetect {
		t.Fatalf("action: got %q, want %q", got.Rules[0].Rule.Action, rule.RuleActionDetect)
	}
	if got.Rules[0].Rule.MaxAlerts != rule.DefaultMaxAlertsPerRule {
		t.Fatalf("max_alerts: got %d, want %d", got.Rules[0].Rule.MaxAlerts, rule.DefaultMaxAlertsPerRule)
	}
	if len(got.Rules[0].AppliedModifiers) != 0 {
		t.Fatalf("applied_modifiers: got %v, want none", got.Rules[0].AppliedModifiers)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(got.Warnings))
	}
	if got.Warnings[0].Kind != "invalid_modifier_skipped" {
		t.Fatalf("warning type: got %q, want %q", got.Warnings[0].Kind, "invalid_modifier_skipped")
	}
	if got.Warnings[0].EntryLabel != "local/bad-max-alerts" {
		t.Fatalf("entry_label: got %q", got.Warnings[0].EntryLabel)
	}
	if got.Warnings[0].Reason == "" {
		t.Fatal("warning reason is empty")
	}
}

func TestMerge_ModifierMaxAlertsAndExceptions(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1",
				rule.Rule{
					RuleID:     "r1",
					EventType:  jobevent.NetworkConnect,
					Condition:  `remote_ip == "evil.com"`,
					Exceptions: `remote_ip == "allow.example.com"`,
					Action:     rule.RuleActionDetect,
					MaxAlerts:  5,
				},
			),
		},
		RuleModifiers: []rule.RuleModifier{
			{
				ModifierID:        "local/modify",
				Targets:           []rule.RuleModifierTarget{{RulesetID: "s1", RuleID: "r1"}},
				OverrideMaxAlerts: intPtr(2),
				AddExceptions:     `remote_ip == "safe.example.com"`,
			},
		},
	})
	if got.Rules[0].Rule.MaxAlerts != 2 {
		t.Fatalf("max_alerts: got %d, want 2", got.Rules[0].Rule.MaxAlerts)
	}
	if got.Rules[0].Rule.Exceptions != `remote_ip == "allow.example.com"` {
		t.Fatalf("base exceptions: got %q", got.Rules[0].Rule.Exceptions)
	}
	if len(got.Rules[0].ExceptionClauses) != 1 {
		t.Fatalf("exception clause count: got %d, want 1", len(got.Rules[0].ExceptionClauses))
	}
	if got.Rules[0].ExceptionClauses[0].Source != `remote_ip == "safe.example.com"` {
		t.Fatalf("added exception source: got %q", got.Rules[0].ExceptionClauses[0].Source)
	}
	if got.Rules[0].ExceptionClauses[0].ModifierIdentity != "local/modify" {
		t.Fatalf("modifier identity: got %q", got.Rules[0].ExceptionClauses[0].ModifierIdentity)
	}
}

func TestMerge_ModifierAddsTargetExclude(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1", rule.Rule{
				RuleID:    "r1",
				EventType: jobevent.ProcessExec,
				Condition: `process_name == "bash"`,
				Action:    rule.RuleActionDetect,
				Target: rule.RuleTarget{
					Exclude: []rule.RuleTargetMatcher{{
						ProviderHost: "github.com",
					}},
				},
			}),
		},
		RuleModifiers: []rule.RuleModifier{{
			ModifierID: "local/exclude",
			Targets:    []rule.RuleModifierTarget{{RulesetID: "s1", RuleID: "r1"}},
			AddTargetExclude: []rule.RuleTargetMatcher{{
				Path: "/acme/private",
			}},
		}},
	})

	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	exclude := got.Rules[0].Rule.Target.Exclude
	if len(exclude) != 2 {
		t.Fatalf("exclude len: got %d, want 2", len(exclude))
	}
	if exclude[0].ProviderHost != "github.com" || exclude[1].Path != "/acme/private" {
		t.Fatalf("exclude: got %#v", exclude)
	}
}

func TestMerge_AppliesScopeDefaultMaxAlertsWhenRuleOmitsValue(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		DefaultMaxAlertsPerRule: 7,
		RuleSets: []rule.RuleSet{
			testSet("s1",
				testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect),
			),
		},
	})
	if got.Rules[0].Rule.MaxAlerts != 7 {
		t.Fatalf("max_alerts: got %d, want 7", got.Rules[0].Rule.MaxAlerts)
	}
}

func TestMerge_KeepsRuleMaxAlertsWhenPresent(t *testing.T) {
	r := testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect)
	r.MaxAlerts = 5
	got := rule.Merge(rule.MergeInput{
		DefaultMaxAlertsPerRule: 7,
		RuleSets: []rule.RuleSet{
			testSet("s1", r),
		},
	})
	if got.Rules[0].Rule.MaxAlerts != 5 {
		t.Fatalf("max_alerts: got %d, want 5", got.Rules[0].Rule.MaxAlerts)
	}
}

func TestMerge_TargetFilter(t *testing.T) {
	tests := []struct {
		name      string
		target    rule.RuleTarget
		host      string
		project   string
		wantRules int
	}{
		{
			name: "include single matcher match passes",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{ProviderHost: "github.com", Path: "acme/repo"}},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 1,
		},
		{
			name: "include single matcher no match drops",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{ProviderHost: "gitlab.com"}},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 0,
		},
		{
			name: "include multiple matchers passes when one matches",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{
					{ProviderHost: "gitlab.com"},
					{ProviderHost: "github.com", Path: "acme/repo"},
				},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 1,
		},
		{
			name: "exclude single matcher drops",
			target: rule.RuleTarget{
				Exclude: []rule.RuleTargetMatcher{{ProviderHost: "github.com"}},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 0,
		},
		{
			name: "exclude wins when include and exclude both match",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{ProviderHost: "github.com"}},
				Exclude: []rule.RuleTargetMatcher{{Path: "acme/repo"}},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 0,
		},
		{
			name:      "nil include and no exclude passes by default",
			target:    rule.RuleTarget{},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 1,
		},
		{
			name: "provider host only compares host",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{ProviderHost: "github.com"}},
			},
			host:      "github.com",
			project:   "other/repo",
			wantRules: 1,
		},
		{
			name: "path only compares prefix",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{Path: "acme/repo"}},
			},
			host:      "gitlab.com",
			project:   "acme/repo/subdir",
			wantRules: 1,
		},
		{
			name: "provider host and path both must match",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{ProviderHost: "github.com", Path: "acme/repo"}},
			},
			host:      "github.com",
			project:   "acme/other",
			wantRules: 0,
		},
		{
			name: "caller passes normalized lowercase host",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{ProviderHost: "github.com"}},
			},
			host:      "GitHub.COM",
			project:   "acme/repo",
			wantRules: 0,
		},
		{
			name: "exclude multiple matchers OR drops when second matches",
			target: rule.RuleTarget{
				Exclude: []rule.RuleTargetMatcher{
					{ProviderHost: "gitlab.com"},
					{Path: "acme/repo"},
				},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 0,
		},
		{
			name: "exclude multiple matchers passes when none match",
			target: rule.RuleTarget{
				Exclude: []rule.RuleTargetMatcher{
					{ProviderHost: "gitlab.com"},
					{Path: "other/repo"},
				},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 1,
		},
		{
			name: "include passes when exclude targets different host",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{ProviderHost: "github.com"}},
				Exclude: []rule.RuleTargetMatcher{{ProviderHost: "gitlab.com"}},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 1,
		},
		{
			name: "path exact match passes",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{Path: "acme/repo"}},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 1,
		},
		{
			name: "path prefix matches sibling repo (HasPrefix has no path-boundary guard)",
			target: rule.RuleTarget{
				Exclude: []rule.RuleTargetMatcher{{Path: "acme/repo"}},
			},
			host:    "github.com",
			project: "acme/repo-fork",
			// Documents current HasPrefix behavior: "acme/repo" prefix
			// matches "acme/repo-fork". Users wanting org-only scoping
			// should write "acme/repo/" with a trailing slash.
			wantRules: 0,
		},
		{
			name: "path with trailing slash matches subpath only",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{Path: "acme/repo/"}},
			},
			host:      "github.com",
			project:   "acme/repo/subdir",
			wantRules: 1,
		},
		{
			name: "path with trailing slash does not match exact parent",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{Path: "acme/repo/"}},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 0,
		},
		{
			name: "path with trailing slash does not match sibling repo",
			target: rule.RuleTarget{
				Exclude: []rule.RuleTargetMatcher{{Path: "acme/repo/"}},
			},
			host:      "github.com",
			project:   "acme/repo-fork",
			wantRules: 1,
		},
		{
			name: "empty matcher in include acts as match-all",
			target: rule.RuleTarget{
				Include: []rule.RuleTargetMatcher{{}},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 1,
		},
		{
			name: "empty matcher in exclude drops everything",
			target: rule.RuleTarget{
				Exclude: []rule.RuleTargetMatcher{{}},
			},
			host:      "github.com",
			project:   "acme/repo",
			wantRules: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.Merge(rule.MergeInput{
				RuleSets: []rule.RuleSet{
					testSet("s1", rule.Rule{
						RuleID:    "r1",
						EventType: jobevent.ProcessExec,
						Condition: `process_name == "bash"`,
						Action:    rule.RuleActionDetect,
						Target:    tt.target,
					}),
				},
				ProviderHost: tt.host,
				ProjectPath:  tt.project,
			})
			if len(got.Rules) != tt.wantRules {
				t.Fatalf("rules: got %d, want %d", len(got.Rules), tt.wantRules)
			}
		})
	}
}

func TestMerge_AppliesSystemDefaultMaxAlertsWhenScopeDefaultMissing(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1",
				testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect),
			),
		},
	})
	if got.Rules[0].Rule.MaxAlerts != rule.DefaultMaxAlertsPerRule {
		t.Fatalf("max_alerts: got %d, want %d", got.Rules[0].Rule.MaxAlerts, rule.DefaultMaxAlertsPerRule)
	}
}

func TestMerge_FallsBackToDefaultWhenResolvedMaxAlertsOutOfRange(t *testing.T) {
	// configured default > ceiling is a defensive case: upstream Validate*
	// functions should reject it, but if it slips through merge keeps the
	// rule alive at the system default rather than dropping it.
	got := rule.Merge(rule.MergeInput{
		DefaultMaxAlertsPerRule: rule.MaxAlertsHardCeiling + 1,
		RuleSets: []rule.RuleSet{
			testSet("s1",
				testRule("r1", jobevent.ProcessExec, rule.RuleActionDetect),
			),
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("rules: got %d, want 1 (rule must not be dropped)", len(got.Rules))
	}
	if got.Rules[0].Rule.MaxAlerts != rule.DefaultMaxAlertsPerRule {
		t.Fatalf("max_alerts fallback: got %d, want %d", got.Rules[0].Rule.MaxAlerts, rule.DefaultMaxAlertsPerRule)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(got.Warnings))
	}
	if got.Warnings[0].Kind != "max_alerts_out_of_range" {
		t.Fatalf("warning type: got %q, want %q", got.Warnings[0].Kind, "max_alerts_out_of_range")
	}
	if got.Warnings[0].Identity != (rule.RuleIdentity{RulesetID: "s1", RuleID: "r1"}) {
		t.Fatalf("warning identity: got %#v", got.Warnings[0].Identity)
	}
}

func TestMerge_ModifierExceptionClausesPreserveOrder(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1",
				rule.Rule{
					RuleID:     "r1",
					EventType:  jobevent.NetworkConnect,
					Condition:  `remote_ip == "evil.com"`,
					Exceptions: `remote_ip == "allow.example.com"`,
					Action:     rule.RuleActionDetect,
				},
			),
		},
		RuleModifiers: []rule.RuleModifier{
			{
				ModifierID:    "local/first",
				Targets:       []rule.RuleModifierTarget{{RulesetID: "s1", RuleID: "r1"}},
				AddExceptions: `remote_ip == "safe.example.com"`,
			},
			{
				ModifierID:    "local/second",
				Targets:       []rule.RuleModifierTarget{{RulesetID: "s1", RuleID: "r1"}},
				AddExceptions: `process_name == "curl"`,
			},
		},
	})

	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if len(got.Rules[0].ExceptionClauses) != 2 {
		t.Fatalf("exception clause count: got %d, want 2", len(got.Rules[0].ExceptionClauses))
	}
	if got.Rules[0].ExceptionClauses[0].ModifierIdentity != "local/first" || got.Rules[0].ExceptionClauses[1].ModifierIdentity != "local/second" {
		t.Fatalf("modifier order: got %#v", got.Rules[0].ExceptionClauses)
	}
}

func TestMerge_PredefinedListsParticipateInContentEquality(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			{
				RulesetID: "s1",
				Lists:     map[string][]string{"domains": {"evil.com"}},
				Rules: []rule.Rule{
					{RuleID: "r1", EventType: jobevent.NetworkConnect, Condition: `remote_ip in list.domains`, Action: rule.RuleActionDetect},
				},
			},
			{
				RulesetID: "s1",
				Lists:     map[string][]string{"domains": {"safe.com"}},
				Rules: []rule.Rule{
					{RuleID: "r1", EventType: jobevent.NetworkConnect, Condition: `remote_ip in list.domains`, Action: rule.RuleActionDetect},
				},
			},
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if got.Rules[0].PredefinedLists["domains"][0] != "evil.com" {
		t.Fatalf("kept predefined list: got %#v, want first rule set list", got.Rules[0].PredefinedLists)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(got.Warnings))
	}
}

func TestMerge_RuleTargetParticipatesInContentEquality(t *testing.T) {
	left := rule.Rule{
		RuleID:    "r1",
		EventType: jobevent.NetworkConnect,
		Condition: `remote_ip in list.domains`,
		Action:    rule.RuleActionDetect,
		Target: rule.RuleTarget{
			Include: []rule.RuleTargetMatcher{{ProviderHost: "github.com"}},
		},
	}
	right := left
	right.Target = rule.RuleTarget{
		Exclude: []rule.RuleTargetMatcher{{Path: "acme/sandbox"}},
	}

	got := rule.Merge(rule.MergeInput{
		ProviderHost: "github.com",
		ProjectPath:  "acme/repo",
		RuleSets: []rule.RuleSet{
			testSet("s1", left),
			testSet("s1", right),
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if len(got.Rules[0].Rule.Target.Include) != 1 {
		t.Fatalf("kept target: got %#v, want first rule target", got.Rules[0].Rule.Target)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(got.Warnings))
	}
	if got.Warnings[0].Kind != "duplicate_identity_diff_content" {
		t.Fatalf("warning type: got %q, want duplicate_identity_diff_content", got.Warnings[0].Kind)
	}
}

func TestMerge_RuleTagsParticipateInContentEquality(t *testing.T) {
	left := rule.Rule{
		RuleID:    "r1",
		EventType: jobevent.NetworkConnect,
		Condition: `remote_ip in list.domains`,
		Action:    rule.RuleActionDetect,
		Tags:      map[string]string{"severity": "low"},
	}
	right := left
	right.Tags = map[string]string{"severity": "high"}

	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			testSet("s1", left),
			testSet("s1", right),
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if got.Rules[0].Rule.Tags["severity"] != "low" {
		t.Fatalf("kept tags: got %#v, want first rule tags", got.Rules[0].Rule.Tags)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(got.Warnings))
	}
	if got.Warnings[0].Kind != "duplicate_identity_diff_content" {
		t.Fatalf("warning type: got %q, want duplicate_identity_diff_content", got.Warnings[0].Kind)
	}
}

func TestMerge_PredefinedListsDifferentKeyCountWarns(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			{
				RulesetID: "s1",
				Lists: map[string][]string{
					"domains": {"evil.com"},
				},
				Rules: []rule.Rule{
					{RuleID: "r1", EventType: jobevent.NetworkConnect, Condition: `remote_ip in list.domains`, Action: rule.RuleActionDetect},
				},
			},
			{
				RulesetID: "s1",
				Lists: map[string][]string{
					"domains": {"evil.com"},
					"paths":   {"/etc/passwd"},
				},
				Rules: []rule.Rule{
					{RuleID: "r1", EventType: jobevent.NetworkConnect, Condition: `remote_ip in list.domains`, Action: rule.RuleActionDetect},
				},
			},
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if _, ok := got.Rules[0].PredefinedLists["paths"]; ok {
		t.Fatalf("kept predefined lists: got %#v, want first rule set lists only", got.Rules[0].PredefinedLists)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(got.Warnings))
	}
}

func TestMerge_PredefinedListsSliceOrderParticipatesInContentEquality(t *testing.T) {
	got := rule.Merge(rule.MergeInput{
		RuleSets: []rule.RuleSet{
			{
				RulesetID: "s1",
				Lists: map[string][]string{
					"domains": {"evil.com", "safe.com"},
				},
				Rules: []rule.Rule{
					{RuleID: "r1", EventType: jobevent.NetworkConnect, Condition: `remote_ip in list.domains`, Action: rule.RuleActionDetect},
				},
			},
			{
				RulesetID: "s1",
				Lists: map[string][]string{
					"domains": {"safe.com", "evil.com"},
				},
				Rules: []rule.Rule{
					{RuleID: "r1", EventType: jobevent.NetworkConnect, Condition: `remote_ip in list.domains`, Action: rule.RuleActionDetect},
				},
			},
		},
	})
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	if got.Rules[0].PredefinedLists["domains"][0] != "evil.com" {
		t.Fatalf("kept predefined list order: got %#v, want first rule set order", got.Rules[0].PredefinedLists)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings: got %d, want 1", len(got.Warnings))
	}
}
