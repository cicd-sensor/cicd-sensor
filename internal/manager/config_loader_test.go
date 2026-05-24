package manager

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantRules int
		wantMods  int
		wantErr   bool
	}{
		{
			name: "multi document file collects rule sets and modifiers",
			body: `
rule_sets:
  - ruleset_id: "global-set"
    rules:
      - rule_id: "detect_bash"
        event_type: "process_exec"
        condition: 'process_name == "bash"'
        action: "detect"
---
rule_modifiers:
  - modifier_id: "global-mod"
    targets:
      - ruleset_id: "global-set"
`,
			wantRules: 1,
			wantMods:  1,
		},
		{
			name: "both top-level keys returns error",
			body: `
rule_sets: []
rule_modifiers: []
`,
			wantErr: true,
		},
		{
			name:    "missing top-level keys returns error",
			body:    `{}`,
			wantErr: true,
		},
		{
			name:    "invalid yaml returns error",
			body:    "rule_sets: [",
			wantErr: true,
		},
		{
			name: "invalid rule set returns error",
			body: `
rule_sets:
  - ruleset_id: ""
    rules: []
`,
			wantErr: true,
		},
		{
			name: "invalid modifier returns error",
			body: `
rule_modifiers:
  - modifier_id: ""
    targets:
      - ruleset_id: "set"
`,
			wantErr: true,
		},
		{
			name:    "empty file returns error",
			body:    "---\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.yaml")
			if err := os.WriteFile(path, []byte(tt.body), 0o644); err != nil {
				t.Fatalf("write rule file: %v", err)
			}

			got, err := LoadRuleSourcesFile(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("load config: %v", err)
			}
			var ruleSetCount, ruleModifierCount int
			for _, source := range got {
				ruleSetCount += len(source.RuleSets)
				ruleModifierCount += len(source.RuleModifiers)
			}
			if ruleSetCount != tt.wantRules {
				t.Fatalf("rule_sets: got %d, want %d", ruleSetCount, tt.wantRules)
			}
			if ruleModifierCount != tt.wantMods {
				t.Fatalf("rule_modifiers: got %d, want %d", ruleModifierCount, tt.wantMods)
			}
		})
	}
}
