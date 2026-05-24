package rulesource

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadRulesFile_RejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	outsidePath := filepath.Join(root, "outside.yaml")
	if err := os.WriteFile(outsidePath, []byte("rule_sets: []\n"), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	linkPath := filepath.Join(rulesDir, "escape.yaml")
	if err := os.Symlink(outsidePath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := LoadRulesFile(linkPath); err == nil {
		t.Fatal("LoadRulesFile followed a symlink outside the rules directory")
	}
}

func TestLoadRulesFile_SingleDocuments(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantSets      int
		wantModifiers int
	}{
		{
			name: "rule_sets",
			body: `
rule_sets:
  - ruleset_id: set-1
    rules:
      - rule_id: detect_bash
        event_type: process_exec
        condition: process.exec_path.endsWith("/bash")
        action: detect
`,
			wantSets: 1,
		},
		{
			name: "rule_modifiers",
			body: `
rule_modifiers:
  - modifier_id: mod-1
    targets:
      - ruleset_id: set-1
    add_exceptions: process.exec_path.endsWith("/sh")
`,
			wantModifiers: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.name+".yaml")
			if err := os.WriteFile(path, []byte(tt.body), 0o644); err != nil {
				t.Fatalf("write rule file: %v", err)
			}

			loaded, err := LoadRulesFile(path)
			if err != nil {
				t.Fatalf("LoadRulesFile: %v", err)
			}
			if got := len(loaded.RuleSets); got != tt.wantSets {
				t.Fatalf("rule_sets: got %d, want %d", got, tt.wantSets)
			}
			if got := len(loaded.RuleModifiers); got != tt.wantModifiers {
				t.Fatalf("rule_modifiers: got %d, want %d", got, tt.wantModifiers)
			}
		})
	}
}

func TestLoadRulesFile_MultiDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.yaml")
	if err := os.WriteFile(path, []byte(`
rule_sets:
  - ruleset_id: set-1
    rules:
      - rule_id: detect_bash
        event_type: process_exec
        condition: process.exec_path.endsWith("/bash")
        action: detect
---
rule_modifiers:
  - modifier_id: mod-1
    targets:
      - ruleset_id: set-1
    add_exceptions: process.exec_path.endsWith("/sh")
`), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	loaded, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	if got := len(loaded.RuleSets); got != 1 {
		t.Fatalf("rule_sets: got %d, want 1", got)
	}
	if got := len(loaded.RuleModifiers); got != 1 {
		t.Fatalf("rule_modifiers: got %d, want 1", got)
	}
}

func TestLoadRulesFile_ComputesRevision(t *testing.T) {
	body := []byte(`
rule_sets:
  - ruleset_id: managed
    rules:
      - rule_id: detect_bash
        event_type: process_exec
        condition: process.exec_path.endsWith("/bash")
        action: detect
---
rule_modifiers:
  - modifier_id: mod-1
    targets:
      - ruleset_id: managed
`)
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	loaded, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	wantRevision := ruleRevision(body)
	if len(loaded.RuleSets) != 1 || loaded.RuleSets[0].Rules[0].RuleID != "detect_bash" {
		t.Fatalf("rule_sets: got %+v", loaded.RuleSets)
	}
	if got := loaded.RuleSets[0].Revision; got != wantRevision {
		t.Fatalf("rule_sets[0].revision: got %q, want %q", got, wantRevision)
	}
	if len(loaded.RuleModifiers) != 1 || loaded.RuleModifiers[0].ModifierID != "mod-1" {
		t.Fatalf("rule_modifiers: got %+v", loaded.RuleModifiers)
	}
	if got := loaded.RuleModifiers[0].Revision; got != wantRevision {
		t.Fatalf("rule_modifiers[0].revision: got %q, want %q", got, wantRevision)
	}
}

func TestLoadRulesFile_RejectsOversize(t *testing.T) {
	body := make([]byte, ruleYAMLMaxBytes+1)
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	_, err := LoadRulesFile(path)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("LoadRulesFile error: got %v, want size cap error", err)
	}
}

func TestLoadRulesFile_MultipleRuleSets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(`
rule_sets:
  - ruleset_id: set-1
    rules:
      - rule_id: detect_bash
        event_type: process_exec
        condition: process.exec_path.endsWith("/bash")
        action: detect
  - ruleset_id: set-2
    rules:
      - rule_id: detect_sh
        event_type: process_exec
        condition: process.exec_path.endsWith("/sh")
        action: detect
---
rule_sets:
  - ruleset_id: set-3
    rules:
      - rule_id: detect_zsh
        event_type: process_exec
        condition: process.exec_path.endsWith("/zsh")
        action: detect
`), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	loaded, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	if got := len(loaded.RuleSets); got != 3 {
		t.Fatalf("rule_sets: got %d, want 3", got)
	}
	wantRevision := loaded.RuleSets[0].Revision
	wantIDs := []string{"set-1", "set-2", "set-3"}
	for i, want := range wantIDs {
		if got := loaded.RuleSets[i].RulesetID; got != want {
			t.Fatalf("rule_sets[%d].ruleset_id: got %q, want %q", i, got, want)
		}
		if got := loaded.RuleSets[i].Revision; got != wantRevision {
			t.Fatalf("rule_sets[%d].revision: got %q, want %q", i, got, wantRevision)
		}
	}
}

func TestLoadRulesFile_MultipleRuleModifiers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modifiers.yaml")
	if err := os.WriteFile(path, []byte(`
rule_modifiers:
  - modifier_id: mod-1
    targets:
      - ruleset_id: set-1
    add_exceptions: process.exec_path.endsWith("/sh")
  - modifier_id: mod-2
    targets:
      - ruleset_id: set-2
    override_action: collect
---
rule_modifiers:
  - modifier_id: mod-3
    targets:
      - ruleset_id: set-3
    disable: true
`), 0o644); err != nil {
		t.Fatalf("write modifiers: %v", err)
	}

	loaded, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	if got := len(loaded.RuleModifiers); got != 3 {
		t.Fatalf("rule_modifiers: got %d, want 3", got)
	}
	wantRevision := loaded.RuleModifiers[0].Revision
	wantIDs := []string{"mod-1", "mod-2", "mod-3"}
	for i, want := range wantIDs {
		if got := loaded.RuleModifiers[i].ModifierID; got != want {
			t.Fatalf("rule_modifiers[%d].modifier_id: got %q, want %q", i, got, want)
		}
		if got := loaded.RuleModifiers[i].Revision; got != wantRevision {
			t.Fatalf("rule_modifiers[%d].revision: got %q, want %q", i, got, wantRevision)
		}
	}
}

func TestLoadRulesFile_RejectsMixedDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.yaml")
	if err := os.WriteFile(path, []byte(`
rule_sets: []
rule_modifiers: []
`), 0o644); err != nil {
		t.Fatalf("write mixed: %v", err)
	}

	_, err := LoadRulesFile(path)
	if err == nil || !strings.Contains(err.Error(), "must not contain both rule_sets and rule_modifiers") {
		t.Fatalf("LoadRulesFile error: got %v, want mixed document error", err)
	}
}

func TestLoadRulesFile_RejectsEmptyDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(path, []byte("---\n---\n"), 0o644); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	_, err := LoadRulesFile(path)
	if err == nil || !strings.Contains(err.Error(), "must contain rule_sets or rule_modifiers") {
		t.Fatalf("LoadRulesFile error: got %v, want empty document error", err)
	}
}

func TestLoadRulesFile_RetriesChangedRead(t *testing.T) {
	restore, sleeps := overrideStableReadForTest(t, []readRootFileResult{
		{data: []byte("not: valid\n")},
		{data: []byte("rule_sets: []\n")},
		{data: []byte("rule_sets: []\n")},
		{data: []byte("rule_sets: []\n")},
	})
	defer restore()

	loaded, err := LoadRulesFile(filepath.Join(t.TempDir(), "rules.yaml"))
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	if len(loaded.RuleSets) != 0 || len(loaded.RuleModifiers) != 0 {
		t.Fatalf("loaded: got %#v, want empty valid bundle", loaded)
	}
	if got, want := *sleeps, []time.Duration{time.Millisecond}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retry sleeps: got %v, want %v", got, want)
	}
}

func TestLoadRulesFile_ErrorsWhenReadNeverStabilizes(t *testing.T) {
	restore, sleeps := overrideStableReadForTest(t, []readRootFileResult{
		{data: []byte("rule_sets: []\n")},
		{data: []byte("rule_modifiers: []\n")},
		{data: []byte("rule_sets: []\n")},
		{data: []byte("rule_modifiers: []\n")},
		{data: []byte("rule_sets: []\n")},
		{data: []byte("rule_modifiers: []\n")},
	})
	defer restore()

	_, err := LoadRulesFile(filepath.Join(t.TempDir(), "rules.yaml"))
	if err == nil || !strings.Contains(err.Error(), "rule file changed during read") {
		t.Fatalf("LoadRulesFile error: got %v, want changed during read", err)
	}
	if got, want := *sleeps, []time.Duration{time.Millisecond, 2 * time.Millisecond}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retry sleeps: got %v, want %v", got, want)
	}
}

type readRootFileResult struct {
	data []byte
	err  error
}

func overrideStableReadForTest(t *testing.T, results []readRootFileResult) (func(), *[]time.Duration) {
	t.Helper()

	originalReadRootFile := readRootFile
	originalMaxAttempts := stableReadMaxAttempts
	originalInitialDelay := stableReadInitialDelay
	originalSleep := sleep
	stableReadMaxAttempts = 3
	stableReadInitialDelay = time.Millisecond
	var sleeps []time.Duration
	sleep = func(d time.Duration) {
		sleeps = append(sleeps, d)
	}

	call := 0
	readRootFile = func(string, string) ([]byte, error) {
		if call >= len(results) {
			return results[len(results)-1].data, results[len(results)-1].err
		}
		result := results[call]
		call++
		return result.data, result.err
	}

	return func() {
		readRootFile = originalReadRootFile
		stableReadMaxAttempts = originalMaxAttempts
		stableReadInitialDelay = originalInitialDelay
		sleep = originalSleep
	}, &sleeps
}

func TestIsRuleFileName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "rules.yaml", want: true},
		{name: "rules.yml", want: true},
		{name: "rules.YAML", want: true},
		{name: "README.md"},
		{name: "rules.yaml.bak"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRuleFileName(tt.name); got != tt.want {
				t.Fatalf("IsRuleFileName(%q): got %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
