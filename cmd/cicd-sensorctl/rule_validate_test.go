package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRuleValidate(t *testing.T) {
	t.Parallel()

	testdataDir := filepath.Join("testdata")

	tests := []struct {
		name           string
		args           []string
		wantCode       int
		wantStdout     string
		wantStderr     []string
		wantErr        string
		wantErrIsUsage bool
	}{
		{
			name:       "valid_single_file",
			args:       []string{filepath.Join(testdataDir, "valid.yaml")},
			wantCode:   0,
			wantStdout: "OK: 1 file(s) bundled and validated\n",
		},
		{
			name:       "valid_directory",
			args:       []string{filepath.Join(testdataDir, "dir-valid")},
			wantCode:   0,
			wantStdout: "OK: 2 file(s) bundled and validated\n",
		},
		{
			name:       "valid_mixed_extensions",
			args:       []string{filepath.Join(testdataDir, "dir-mixed")},
			wantCode:   0,
			wantStdout: "OK: 2 file(s) bundled and validated\n",
		},
		{
			name:       "missing_required_field",
			args:       []string{filepath.Join(testdataDir, "invalid_missing_field.yaml")},
			wantCode:   1,
			wantErr:    "rule validate: bundle failed validation",
			wantStderr: []string{"ruleset_id is required"},
		},
		{
			name:       "duplicate_rule_id",
			args:       []string{filepath.Join(testdataDir, "invalid_duplicate_rule_id.yaml")},
			wantCode:   1,
			wantErr:    "rule validate: bundle failed validation",
			wantStderr: []string{"duplicate rule_id"},
		},
		{
			name:       "invalid_cel_syntax",
			args:       []string{filepath.Join(testdataDir, "invalid_cel.yaml")},
			wantCode:   1,
			wantErr:    "rule validate: bundle failed validation",
			wantStderr: []string{"ruleset_id=set-invalid-cel rule_id=bad_cel", "Syntax error"},
		},
		{
			name:       "forbidden_cel_operator",
			args:       []string{filepath.Join(testdataDir, "invalid_forbidden_call.yaml")},
			wantCode:   1,
			wantErr:    "rule validate: bundle failed validation",
			wantStderr: []string{"ruleset_id=set-invalid-forbidden rule_id=no_timestamp", "found no matching overload for 'timestamp'"},
		},
		{
			name:       "nonexistent_path",
			args:       []string{filepath.Join(testdataDir, "does-not-exist.yaml")},
			wantCode:   2,
			wantErr:    "stat " + filepath.Join(testdataDir, "does-not-exist.yaml"),
			wantStderr: nil,
		},
		{
			name:       "non_yaml_file",
			args:       []string{filepath.Join(testdataDir, "not_yaml.txt")},
			wantCode:   2,
			wantErr:    "not a YAML file",
			wantStderr: nil,
		},
		{
			name:           "empty_args",
			wantCode:       2,
			wantErr:        "rule validate: at least one path is required",
			wantErrIsUsage: true,
		},
		{
			name:       "empty_directory_has_no_yaml_files",
			args:       []string{filepath.Join(testdataDir, "dir-empty")},
			wantCode:   1,
			wantErr:    "rule validate: no YAML rule files found",
			wantStderr: nil,
		},
		{
			name:       "high_cost_rule_warns_but_passes",
			args:       []string{filepath.Join(testdataDir, "high_cost.yaml")},
			wantCode:   0,
			wantStdout: "OK: 1 file(s) bundled and validated\n",
			wantStderr: []string{"warning:", "ruleset_id=set-high-cost rule_id=nested_contains", "condition estimated CEL cost", "exceeds 5000"},
		},
		{
			name:       "high_cost_exception_warns_but_passes",
			args:       []string{filepath.Join(testdataDir, "high_cost_exception.yaml")},
			wantCode:   0,
			wantStdout: "OK: 1 file(s) bundled and validated\n",
			wantStderr: []string{"warning:", "ruleset_id=set-high-cost-exc rule_id=cheap_condition_with_expensive_exception", "exception estimated CEL cost", "exceeds 5000"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code, err := runRuleValidate(context.Background(), tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d", code, tt.wantCode)
			}
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error: got %q, want substring %q", err.Error(), tt.wantErr)
				}
				if tt.wantErrIsUsage {
					var usageErr *cliUsageError
					if !errors.As(err, &usageErr) {
						t.Fatalf("error type: got %T, want *cliUsageError", err)
					}
				}
			}

			if got := stdout.String(); got != tt.wantStdout {
				t.Fatalf("stdout: got %q, want %q", got, tt.wantStdout)
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("stderr: got %q, want substring %q", stderr.String(), want)
				}
			}
		})
	}
}

func TestRunRuleValidateRepositoryRules(t *testing.T) {
	t.Parallel()

	rulesPath := filepath.Join("..", "..", "rules")
	files, _, err := collectRuleFiles([]string{rulesPath})
	if err != nil {
		t.Fatalf("collect repository rules: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("repository rules: got 0 files")
	}

	var stdout, stderr bytes.Buffer
	code, err := runRuleValidate(context.Background(), []string{rulesPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0; stderr=%q err=%v", code, stderr.String(), err)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := stdout.String(), fmt.Sprintf("OK: %d file(s) bundled and validated\n", len(files)); got != want {
		t.Fatalf("stdout: got %q, want %q", got, want)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr: got %q, want empty", got)
	}
}

func TestRunRuleValidate_BundledDuplicateAcrossFiles(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	writeTestRuleFile(t, rulesDir, "a.yaml", `
rule_sets:
  - ruleset_id: set-dup
    rules:
      - rule_id: same_rule
        event_type: process_exec
        condition: process.exec_path.endsWith("/bash")
        action: detect
`)
	writeTestRuleFile(t, rulesDir, "b.yaml", `
rule_sets:
  - ruleset_id: set-dup
    rules:
      - rule_id: same_rule
        event_type: process_exec
        condition: process.exec_path.endsWith("/sh")
        action: detect
`)

	var stdout, stderr bytes.Buffer
	code, err := runRuleValidate(context.Background(), []string{rulesDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stderr.String(), "ruleset_id=set-dup rule_id=same_rule") {
		t.Fatalf("stderr: got %q, want duplicate identity", stderr.String())
	}
	if !strings.Contains(stderr.String(), "duplicate_identity_diff_content") {
		t.Fatalf("stderr: got %q, want duplicate warning", stderr.String())
	}
	if got, want := stdout.String(), "OK: 2 file(s) bundled and validated\n"; got != want {
		t.Fatalf("stdout: got %q, want %q", got, want)
	}
}

func TestRunRuleValidate_BundleWhitespaceOnlyFileFails(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	writeTestRuleFile(t, rulesDir, "empty.yaml", "\n \n")

	var stdout, stderr bytes.Buffer
	code, err := runRuleValidate(context.Background(), []string{rulesDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code: got %d, want 1", code)
	}
	if err == nil || !strings.Contains(err.Error(), "bundle failed validation") {
		t.Fatalf("error: got %v, want bundle failed validation", err)
	}
	if !strings.Contains(stderr.String(), "must contain rule_sets or rule_modifiers") {
		t.Fatalf("stderr: got %q, want empty document validation", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout: got %q, want empty", stdout.String())
	}
}

func TestDispatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr []string
	}{
		{
			name:       "help",
			args:       []string{"help"},
			wantCode:   0,
			wantStdout: "Usage:\n  cicd-sensorctl rule validate <path>...\n  cicd-sensorctl rule bundle --input-dir DIR --output-file FILE\n  cicd-sensorctl token generate\n  cicd-sensorctl report attest [--output-file FILE]\n  cicd-sensorctl report html [--output-file FILE]\n  cicd-sensorctl report stepsummary [--html-url URL] [--debug-url URL] [--health-failed]\n",
		},
		{
			name:       "no_args",
			wantCode:   2,
			wantStderr: []string{"Usage:\n  cicd-sensorctl rule validate <path>...\n  cicd-sensorctl rule bundle --input-dir DIR --output-file FILE\n  cicd-sensorctl token generate\n  cicd-sensorctl report attest [--output-file FILE]"},
		},
		{
			name:       "unknown_command",
			args:       []string{"bogus"},
			wantCode:   2,
			wantStderr: []string{"unknown command: bogus", "Usage:\n  cicd-sensorctl rule validate <path>...\n  cicd-sensorctl rule bundle --input-dir DIR --output-file FILE\n  cicd-sensorctl token generate\n  cicd-sensorctl report attest [--output-file FILE]"},
		},
		{
			name:       "unknown_rule_subcommand",
			args:       []string{"rule", "bogus"},
			wantCode:   2,
			wantStderr: []string{"unknown rule subcommand: bogus", "Usage:\n  cicd-sensorctl rule validate <path>...\n  cicd-sensorctl rule bundle --input-dir DIR --output-file FILE\n  cicd-sensorctl token generate\n  cicd-sensorctl report attest [--output-file FILE]"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tt.args, nil, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d", code, tt.wantCode)
			}
			if got := stdout.String(); got != tt.wantStdout {
				t.Fatalf("stdout: got %q, want %q", got, tt.wantStdout)
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("stderr: got %q, want substring %q", stderr.String(), want)
				}
			}
		})
	}
}

func TestCollectRuleFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	subDir := filepath.Join(root, "rules")
	if err := os.MkdirAll(filepath.Join(subDir, "nested"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "a.yaml"), []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile a.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "nested", "b.yml"), []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile b.yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "ignore.txt"), []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile ignore.txt: %v", err)
	}

	files, skipped, err := collectRuleFiles([]string{subDir, filepath.Join(subDir, "a.yaml")})
	if err != nil {
		t.Fatalf("collectRuleFiles: %v", err)
	}

	wantFiles := []string{filepath.Join(subDir, "a.yaml")}
	var gotFiles []string
	for _, file := range files {
		gotFiles = append(gotFiles, file.Path)
	}
	if strings.Join(gotFiles, "\n") != strings.Join(wantFiles, "\n") {
		t.Fatalf("files:\n got: %q\nwant: %q", gotFiles, wantFiles)
	}

	wantSkipped := []string{filepath.Join(subDir, "nested")}
	var gotSkipped []string
	for _, dir := range skipped {
		gotSkipped = append(gotSkipped, dir.Path)
	}
	if strings.Join(gotSkipped, "\n") != strings.Join(wantSkipped, "\n") {
		t.Fatalf("skipped:\n got: %q\nwant: %q", gotSkipped, wantSkipped)
	}
}

func TestCollectRuleFiles_DeduplicatesRepeatedFile(t *testing.T) {
	t.Parallel()

	rulePath := filepath.Join(t.TempDir(), "a.yaml")
	if err := os.WriteFile(rulePath, []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	files, skipped, err := collectRuleFiles([]string{rulePath, rulePath})
	if err != nil {
		t.Fatalf("collectRuleFiles: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped: got %v, want empty", skipped)
	}
	if len(files) != 1 {
		t.Fatalf("files: got %d, want 1 (%v)", len(files), files)
	}
	if files[0].Path != rulePath {
		t.Fatalf("file path: got %q, want %q", files[0].Path, rulePath)
	}
}
