package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	code, err := dispatch(ctx, args, stdin, stdout, stderr)
	if err == nil {
		return code
	}

	var usageErr *cliUsageError
	if errors.As(err, &usageErr) {
		if usageErr.message != "" {
			fmt.Fprintln(stderr, usageErr.message)
		}
		printUsage(stderr)
		return usageErr.code
	}

	fmt.Fprintln(stderr, err)
	return code
}

func dispatch(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, newUsageError(2, "")
	}

	switch args[0] {
	case "rule":
		return runRule(ctx, args[1:], stdout, stderr)
	case "token":
		return runToken(ctx, args[1:], stdout, stderr)
	case "report":
		return runReport(ctx, args[1:], stdin, stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0, nil
	default:
		return 2, newUsageError(2, fmt.Sprintf("unknown command: %s", args[0]))
	}
}

func runReport(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, newUsageError(2, "report: subcommand is required")
	}

	switch args[0] {
	case "attest":
		return runReportAttest(ctx, args[1:], stdin, stdout, stderr)
	case "html":
		return runReportHTML(ctx, args[1:], stdin, stdout, stderr)
	case "stepsummary":
		return runReportStepSummary(ctx, args[1:], stdin, stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0, nil
	default:
		return 2, newUsageError(2, fmt.Sprintf("unknown report subcommand: %s", args[0]))
	}
}

func runRule(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, newUsageError(2, "rule: subcommand is required")
	}

	switch args[0] {
	case "validate":
		return runRuleValidate(ctx, args[1:], stdout, stderr)
	case "bundle":
		return runRuleBundle(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0, nil
	default:
		return 2, newUsageError(2, fmt.Sprintf("unknown rule subcommand: %s", args[0]))
	}
}

func runToken(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, newUsageError(2, "token: subcommand is required")
	}

	switch args[0] {
	case "generate":
		return runTokenGenerate(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0, nil
	default:
		return 2, newUsageError(2, fmt.Sprintf("unknown token subcommand: %s", args[0]))
	}
}

type cliUsageError struct {
	code    int
	message string
}

func (e *cliUsageError) Error() string {
	return e.message
}

func newUsageError(code int, message string) error {
	return &cliUsageError{code: code, message: message}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  cicd-sensorctl rule validate <path>...")
	fmt.Fprintln(w, "  cicd-sensorctl rule bundle --input-dir DIR --output PATH")
	fmt.Fprintln(w, "  cicd-sensorctl token generate")
	fmt.Fprintln(w, "  cicd-sensorctl report attest [--output-path PATH]")
	fmt.Fprintln(w, "  cicd-sensorctl report html [--output-path PATH]")
	fmt.Fprintln(w, "  cicd-sensorctl report stepsummary [--html-url URL] [--debug-url URL] [--health-failed]")
}
