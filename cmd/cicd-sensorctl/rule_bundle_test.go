package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestRunRuleBundle(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	writeTestRuleFile(t, rulesDir, "b.yml", `
rule_modifiers:
  - modifier_id: add_shell_exception
    targets:
      - ruleset_id: set-a
    add_exceptions: process.exec_path.endsWith("/sh")
`)
	writeTestRuleFile(t, rulesDir, "a.yaml", `
rule_sets:
  - ruleset_id: set-a
    rules:
      - rule_id: detect_bash
        event_type: process_exec
        condition: process.exec_path.endsWith("/bash")
        action: detect
`)
	writeTestRuleFile(t, rulesDir, "c.yaml", `
rule_sets:
  - ruleset_id: set-c
    rules:
      - rule_id: detect_tcp
        event_type: network_connect
        condition: protocol == "tcp"
        action: collect
`)
	if err := os.WriteFile(filepath.Join(rulesDir, "ignore.txt"), []byte("ignored"), 0o644); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(rulesDir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	outputFile := filepath.Join(t.TempDir(), "rules.yaml")
	var stdout, stderr bytes.Buffer
	code, err := runRuleBundle(context.Background(), []string{"--input-dir", rulesDir, "--output-file", outputFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0; stderr=%q err=%v", code, stderr.String(), err)
	}
	if err != nil {
		t.Fatalf("runRuleBundle: %v", err)
	}
	if !strings.Contains(stdout.String(), "OK: 3 file(s) bundled into "+outputFile) {
		t.Fatalf("stdout: got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Next: cicd-sensorctl rule validate "+outputFile) {
		t.Fatalf("stdout: got %q, want validate hint", stdout.String())
	}
	if !strings.Contains(stderr.String(), "subdirectory skipped") {
		t.Fatalf("stderr: got %q, want subdirectory warning", stderr.String())
	}

	loaded, err := rulesource.LoadRulesFile(outputFile)
	if err != nil {
		t.Fatalf("LoadRulesFile generated bundle: %v", err)
	}
	if got := len(loaded.RuleSets); got != 2 {
		t.Fatalf("rule_sets: got %d, want 2", got)
	}
	if got := len(loaded.RuleModifiers); got != 1 {
		t.Fatalf("rule_modifiers: got %d, want 1", got)
	}
	if got, want := loaded.RuleSets[0].RulesetID, "set-a"; got != want {
		t.Fatalf("first ruleset_id: got %q, want %q", got, want)
	}
}

func TestRunRuleBundleUsageAndInputErrors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules")
	if err := os.Mkdir(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	writeTestRuleFile(t, rulesDir, "valid.yaml", `
rule_sets:
  - ruleset_id: set-valid
    rules:
      - rule_id: detect_bash
        event_type: process_exec
        condition: process.exec_path.endsWith("/bash")
        action: detect
`)
	emptyRulesDir := filepath.Join(root, "empty-rules")
	if err := os.Mkdir(emptyRulesDir, 0o755); err != nil {
		t.Fatalf("mkdir empty rules: %v", err)
	}
	rulePath := filepath.Join(root, "rule.yaml")
	writeTestRuleFile(t, root, "rule.yaml", `
rule_sets:
  - ruleset_id: set-a
    rules:
      - rule_id: detect_bash
        event_type: process_exec
        condition: process.exec_path.endsWith("/bash")
        action: detect
`)
	existingOutput := filepath.Join(root, "existing.yaml")
	if err := os.WriteFile(existingOutput, []byte("existing"), 0o644); err != nil {
		t.Fatalf("write existing output: %v", err)
	}
	missingOutputDir := filepath.Join(root, "missing", "out.yaml")

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing_directory",
			args:    []string{"--output-file", filepath.Join(root, "out.yaml")},
			wantErr: "--input-dir is required",
		},
		{
			name:    "unknown_flag",
			args:    []string{"--input-dir", rulesDir, "--output-file", filepath.Join(root, "out.yaml"), "--bogus"},
			wantErr: "flag provided but not defined",
		},
		{
			name:    "unexpected_positional_arg",
			args:    []string{"--input-dir", rulesDir, "--output-file", filepath.Join(root, "out.yaml"), "extra"},
			wantErr: "unexpected positional arguments",
		},
		{
			name:    "missing_output",
			args:    []string{"--input-dir", rulesDir},
			wantErr: "--output-file is required",
		},
		{
			name:    "file_input",
			args:    []string{"--input-dir", rulePath, "--output-file", filepath.Join(root, "out.yaml")},
			wantErr: "is not a directory",
		},
		{
			name:    "existing_output",
			args:    []string{"--input-dir", rulesDir, "--output-file", existingOutput},
			wantErr: "output file already exists",
		},
		{
			name:    "missing_output_directory",
			args:    []string{"--input-dir", rulesDir, "--output-file", missingOutputDir},
			wantErr: "write rule bundle",
		},
		{
			name:    "output_inside_input_dir",
			args:    []string{"--input-dir", rulesDir, "--output-file", filepath.Join(rulesDir, "bundle.yaml")},
			wantErr: "output file must be outside",
		},
		{
			name:    "empty_directory",
			args:    []string{"--input-dir", emptyRulesDir, "--output-file", filepath.Join(root, "empty-out.yaml")},
			wantErr: "no YAML rule files found",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code, err := runRuleBundle(context.Background(), tt.args, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("exit code: got 0, want failure")
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error: got %v, want containing %q", err, tt.wantErr)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout: got %q, want empty", stdout.String())
			}
		})
	}
}

func TestRunRuleBundleHelp(t *testing.T) {
	t.Parallel()

	for _, arg := range []string{"-h", "--help"} {
		arg := arg
		t.Run(arg, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code, err := runRuleBundle(context.Background(), []string{arg}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit code: got %d, want 0", code)
			}
			if err != nil {
				t.Fatalf("runRuleBundle: %v", err)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout: got %q, want empty", got)
			}
			if !strings.Contains(stderr.String(), "cicd-sensorctl rule bundle --input-dir DIR --output-file FILE") {
				t.Fatalf("stderr: got %q, want usage", stderr.String())
			}
		})
	}
}

func writeTestRuleFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
