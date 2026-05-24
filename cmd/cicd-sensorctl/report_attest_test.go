package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

func sampleSummaryLog() resultdoc.JobEventSummaryForReport {
	return resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity(
			"github.com", "acme/example", "123", "build", "1", "runner-1",
		),
		Metadata:       jobcontext.JobMetadata{},
		RunnerType:     "machine",
		StartedAt:      time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
		GeneratedAt:    time.Date(2026, 4, 30, 12, 5, 0, 0, time.UTC),
		FinalizeReason: "shutdown",
		ResultSummary: resultdoc.ResultSummary{
			Result:    resultdoc.ResultDetected,
			HitsCount: 1,
		},
		NetworkConnections: []resultdoc.NetworkConnection{{
			RemoteIP:   "8.8.8.8",
			RemotePort: 443,
			Protocol:   "tcp",
		}},
		DomainObservations: []resultdoc.DomainObservation{{Domain: "dns.google"}},
		Hits: []resultdoc.HitRecord{
			{
				RulesetID: "set",
				RuleID:    "curl-egress",
				RuleName:  "curl egress",
				Action:    "detect",
				Timestamp: time.Date(2026, 4, 30, 12, 3, 0, 0, time.UTC),
			},
		},
	}
}

func TestRunReportAttest_StdinHappyPath(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(sampleSummaryLog())
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code, err := runReportAttest(context.Background(), nil, bytes.NewReader(body), &stdout, &stderr)
	if err != nil {
		t.Fatalf("runReportAttest: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}

	got := stdout.String()
	if !json.Valid([]byte(strings.TrimSpace(got))) {
		t.Fatalf("output is not valid JSON: %s", got)
	}
	if !strings.Contains(got, `"monitorLog"`) {
		t.Fatalf("missing monitorLog in output:\n%s", got)
	}
}

func TestRunReportAttest_OutputFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outputFile := filepath.Join(dir, "attestation.json")
	body, err := json.Marshal(sampleSummaryLog())
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code, err := runReportAttest(
		context.Background(),
		[]string{"--output-file", outputFile},
		bytes.NewReader(body),
		&stdout, &stderr,
	)
	if err != nil {
		t.Fatalf("runReportAttest: %v", err)
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
	if !json.Valid(bytes.TrimSpace(written)) {
		t.Fatalf("output file is not valid JSON: %s", written)
	}
}

func TestRunReportAttest_InvalidJSON(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportAttest(context.Background(), nil, strings.NewReader("not json"), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if code == 0 {
		t.Fatalf("exit code: got 0, want non-zero")
	}
}

func TestRunReportAttest_ReadError(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportAttest(context.Background(), nil, errReader{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code: got %d, want 1", code)
	}
	if err == nil || !strings.Contains(err.Error(), "read input") {
		t.Fatalf("error: got %v, want read input error", err)
	}
}

func TestRunReportAttest_WriteError(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(sampleSummaryLog())
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code, err := runReportAttest(
		context.Background(),
		[]string{"--output-file", filepath.Join(t.TempDir(), "missing", "attestation.json")},
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

func TestRunReportAttest_UnknownFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportAttest(context.Background(), []string{"--bogus"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code: got %d, want 2", code)
	}
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("error: got %v, want unknown flag error", err)
	}
}

func TestRunReportAttest_TooManyArgs(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportAttest(
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

func TestRunReportAttest_Help(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code, err := runReportAttest(context.Background(), []string{"-h"}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runReportAttest: got error %v, want nil", err)
	}
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout: got %q, want empty", stdout.String())
	}
	for _, want := range []string{
		"usage: cicd-sensorctl report attest [flags]",
		"Input:",
		"Reads summary_log JSON from stdin.",
		"Optional:",
		"File to write runtime-trace attestation JSON to. Writes to stdout when empty.",
		"--output-file",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr: got %q, want substring %q", stderr.String(), want)
		}
	}
}
