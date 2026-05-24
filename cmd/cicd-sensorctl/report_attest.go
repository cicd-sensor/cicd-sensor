package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cicd-sensor/cicd-sensor/internal/ctl/report"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

// runReportAttest reads a project result JSON document (from stdin or the
// given file) and writes the runtime-trace attestation predicate as JSON
// to stdout (or --output-file).
func runReportAttest(_ context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	opts, err := parseReportIOArgs("report attest", args, stderr, "runtime-trace attestation JSON")
	if err != nil {
		return 2, err
	}
	if opts.help {
		return 0, nil
	}

	input, err := readReportInput(stdin)
	if err != nil {
		return 1, fmt.Errorf("read input: %w", err)
	}

	var projectResult resultdoc.JobEventSummaryForReport
	if err := json.Unmarshal(input, &projectResult); err != nil {
		return 1, fmt.Errorf("decode project result: %w", err)
	}

	var buf bytes.Buffer
	if err := report.RenderAttestation(&buf, &projectResult); err != nil {
		return 1, fmt.Errorf("render attestation: %w", err)
	}

	if err := writeReportOutput(opts, buf.Bytes(), stdout); err != nil {
		return 1, fmt.Errorf("write output: %w", err)
	}
	return 0, nil
}
