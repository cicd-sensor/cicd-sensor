package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"

	"github.com/cicd-sensor/cicd-sensor/internal/ctl/report"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

type reportStepSummaryOptions struct {
	htmlURL      string
	healthFailed bool
	help         bool
}

// runReportStepSummary renders GitHub Step Summary HTML for cicd-sensor-action.
func runReportStepSummary(_ context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	opts, err := parseReportStepSummaryArgs(args, stderr)
	if err != nil {
		return 2, err
	}
	if opts.help {
		return 0, nil
	}

	htmlURL, err := trustedStepSummaryURL(opts.htmlURL)
	if err != nil {
		return 1, fmt.Errorf("html-url: %w", err)
	}

	var input []byte
	if stdin != nil {
		input, err = readReportInput(stdin)
		if err != nil {
			return 1, fmt.Errorf("read input: %w", err)
		}
	}

	var projectResult resultdoc.JobEventSummaryForReport
	if len(bytes.TrimSpace(input)) > 0 {
		if err := json.Unmarshal(input, &projectResult); err != nil {
			return 1, fmt.Errorf("decode project result: %w", err)
		}
	}

	if err := report.RenderStepSummary(stdout, projectResult, report.StepSummaryOptions{
		HTMLURL:      htmlURL,
		HealthFailed: opts.healthFailed,
	}); err != nil {
		return 1, err
	}
	return 0, nil
}

func parseReportStepSummaryArgs(args []string, stderr io.Writer) (reportStepSummaryOptions, error) {
	var opts reportStepSummaryOptions
	fs := flag.NewFlagSet("report stepsummary", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: cicd-sensorctl report stepsummary [flags]")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Input:")
		fmt.Fprintln(fs.Output(), "  Reads project result JSON from stdin when available.")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Optional:")
		fmt.Fprintln(fs.Output(), "  --html-url URL")
		fmt.Fprintln(fs.Output(), "        Trusted URL for the uploaded HTML report artifact.")
		fmt.Fprintln(fs.Output(), "  --health-failed")
		fmt.Fprintln(fs.Output(), "        Render an agent health-failure summary.")
	}
	fs.StringVar(&opts.htmlURL, "html-url", "", "Trusted URL for the HTML report artifact.")
	fs.BoolVar(&opts.healthFailed, "health-failed", false, "Render health-failure summary.")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.help = true
			return opts, nil
		}
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, newUsageError(2, "report stepsummary: too many arguments")
	}
	return opts, nil
}

func trustedStepSummaryURL(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("missing host")
	}
	return u.String(), nil
}
