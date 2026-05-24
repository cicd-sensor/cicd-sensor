package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunReportHTML_StdinHappyPath(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(sampleSummaryLog())
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code, err := runReportHTML(context.Background(), nil, bytes.NewReader(body), &stdout, &stderr)
	if err != nil {
		t.Fatalf("runReportHTML: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}

	got := stdout.String()
	wantFragments := []string{
		"<!doctype html>",
		"window.REPORT_DATA",
		"JSON.parse(",
		"cicd-sensor Report",
		// Result document fields land in the embedded JSON.
		`\"ruleset_id\":\"set\"`,
		`\"rule_id\":\"curl-egress\"`,
		`\"acme/example\"`,
		`\"detected\"`,
	}
	for _, fragment := range wantFragments {
		if !strings.Contains(got, fragment) {
			t.Fatalf("missing fragment %q in output:\n%s", fragment, got)
		}
	}
}

func TestRunReportHTML_OutputFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outputFile := filepath.Join(dir, "report.html")
	body, err := json.Marshal(sampleSummaryLog())
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code, err := runReportHTML(
		context.Background(),
		[]string{"--output-file", outputFile},
		bytes.NewReader(body),
		&stdout, &stderr,
	)
	if err != nil {
		t.Fatalf("runReportHTML: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty when --output-file is set, got %s", stdout.String())
	}

	written, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(written), "<!doctype html>") {
		t.Fatalf("output file is not HTML: %s", written)
	}
}

func TestRunReportHTML_InvalidJSON(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportHTML(context.Background(), nil, strings.NewReader("not json"), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if code == 0 {
		t.Fatalf("exit code: got 0, want non-zero")
	}
}

func TestRunReportHTML_ReadError(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportHTML(context.Background(), nil, errReader{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code: got %d, want 1", code)
	}
	if err == nil || !strings.Contains(err.Error(), "read input") {
		t.Fatalf("error: got %v, want read input error", err)
	}
}

func TestRunReportHTML_WriteError(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(sampleSummaryLog())
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code, err := runReportHTML(
		context.Background(),
		[]string{"--output-file", filepath.Join(t.TempDir(), "missing", "report.html")},
		bytes.NewReader(body),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("exit code: got %d, want 1", code)
	}
	if err == nil || !strings.Contains(err.Error(), "write output") {
		t.Fatalf("error: got %v, want write output error", err)
	}
}

func TestRunReportHTML_UnknownFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportHTML(context.Background(), []string{"--bogus"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code: got %d, want 2", code)
	}
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("error: got %v, want unknown flag error", err)
	}
}

func TestRunReportHTML_TooManyArgs(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportHTML(
		context.Background(),
		[]string{"extra.json"},
		nil,
		&stdout, &stderr,
	)
	if err == nil {
		t.Fatal("expected usage error for two positional args")
	}
	if code != 2 {
		t.Fatalf("exit code: got %d, want 2", code)
	}
}

func TestRunReportHTML_Help(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportHTML(context.Background(), []string{"-h"}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runReportHTML: got error %v, want nil", err)
	}
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout: got %q, want empty", stdout.String())
	}
	for _, want := range []string{
		"usage: cicd-sensorctl report html [flags]",
		"Input:",
		"Reads summary_log JSON from stdin.",
		"Optional:",
		"File to write a self-contained HTML report to. Writes to stdout when empty.",
		"--output-file",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr: got %q, want substring %q", stderr.String(), want)
		}
	}
}
