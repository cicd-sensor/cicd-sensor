package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const (
	jobUsage       = "usage: cicd-sensor job health [flags]"
	jobHealthUsage = "usage: cicd-sensor job health [flags]"
)

func runJobSubcommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, jobUsage)
		os.Exit(2)
	}
	switch args[0] {
	case "health":
		runJobHealth(args[1:])
	default:
		fmt.Fprintln(os.Stderr, jobUsage)
		os.Exit(2)
	}
}

func runJobHealth(args []string) {
	fs := flag.NewFlagSet("job health", flag.ExitOnError)
	socketPath := defaultSocketPath
	var identity jobIdentityFlags
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), jobHealthUsage)
		fmt.Fprintln(fs.Output())
		printGitHubIdentityEnvHelp(fs.Output())
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Equivalent identity flags:")
		fmt.Fprintln(fs.Output(), "  --provider github")
		fmt.Fprintln(fs.Output(), "        CI provider. GitLab job health is Phase 2.")
		fmt.Fprintln(fs.Output(), "  --provider-host HOST")
		fmt.Fprintln(fs.Output(), "        Normalized CI provider host.")
		fmt.Fprintln(fs.Output(), "  --project-path PATH")
		fmt.Fprintln(fs.Output(), "        Provider project path, e.g. acme/example.")
		fmt.Fprintln(fs.Output(), "  --github-run-id ID")
		fmt.Fprintln(fs.Output(), "        GitHub Actions run ID.")
		fmt.Fprintln(fs.Output(), "  --github-run-attempt N")
		fmt.Fprintln(fs.Output(), "        GitHub Actions run attempt.")
		fmt.Fprintln(fs.Output(), "  --github-job NAME")
		fmt.Fprintln(fs.Output(), "        GitHub Actions job name.")
		fmt.Fprintln(fs.Output(), "  --github-runner-tracking-id ID")
		fmt.Fprintln(fs.Output(), "        GitHub runner tracking ID.")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Optional flags:")
		fmt.Fprintf(fs.Output(), "  --socket PATH\n        Agent control socket path. (default %q)\n", defaultSocketPath)
	}
	fs.StringVar(&socketPath, "socket", socketPath, "Agent control socket path.")
	registerJobIdentityFlags(fs, &identity)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, jobHealthUsage)
		os.Exit(2)
	}
	applyGitHubEnvFallback(&identity)
	if err := requireGitHubProvider(identity, "job health supports only provider github; GitLab job health is Phase 2"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	req, err := buildJobHealthRequest(identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := postSocket(ctx, socketPath, "/v1/github/job/health", req); err != nil {
		fmt.Fprintf(os.Stderr, "job health: %v\n", err)
		os.Exit(1)
	}
}

func buildJobHealthRequest(identity jobIdentityFlags) (map[string]string, error) {
	return buildJobIdentityRequest(identity)
}
