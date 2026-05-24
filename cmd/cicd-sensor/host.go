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
	hostUsage      = "usage: cicd-sensor host start|end [flags]"
	hostStartUsage = "usage: cicd-sensor host start [flags]"
	hostEndUsage   = "usage: cicd-sensor host end [flags]"
)

// runHostStart is the explicit host-side Job registration path for GitHub
// self-hosted runners: the wrapper calls it at Job start so the agent can bind
// the runner cgroup immediately. GitLab Container Executor does not use this
// CLI path; its dockerd proxy creates Jobs through /v1/gitlab/host/start when
// it first sees a container for an unregistered GitLab Job.
func runHostSubcommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, hostUsage)
		os.Exit(2)
	}

	switch args[0] {
	case "start":
		runHostStart(args[1:])
	case "end":
		runHostEnd(args[1:])
	default:
		fmt.Fprintln(os.Stderr, hostUsage)
		os.Exit(2)
	}
}

func runHostStart(args []string) {
	fs := flag.NewFlagSet("host start", flag.ExitOnError)
	socketPath := defaultSocketPath
	var identity jobIdentityFlags
	var metadata jobMetadataFlags
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), hostStartUsage)
		fmt.Fprintln(fs.Output())
		printGitHubIdentityEnvHelp(fs.Output())
		fmt.Fprintln(fs.Output())
		printGitHubMetadataEnvHelp(fs.Output())
		fmt.Fprintln(fs.Output())
		printRequiredIdentityFlagsHelp(fs.Output(), "CI provider. GitLab host start is driven by the dockerd proxy.")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Optional flags:")
		fmt.Fprintf(fs.Output(), "  --socket PATH\n        Agent control socket path. (default %q)\n", defaultSocketPath)
		fmt.Fprintln(fs.Output())
		printOptionalMetadataFlagsHelp(fs.Output())
	}
	fs.StringVar(&socketPath, "socket", socketPath, "Agent control socket path.")
	registerJobIdentityFlags(fs, &identity)
	registerJobMetadataFlags(fs, &metadata)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, hostStartUsage)
		os.Exit(2)
	}
	applyGitHubEnvFallback(&identity)
	applyGitHubMetadataEnvFallback(&metadata)

	if err := requireGitHubProvider(identity, "host start supports only provider github; GitLab host start is handled by proxy dockerd"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	identityReq, err := buildJobIdentityRequest(identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		os.Exit(1)
	}
	req := make(map[string]any, len(identityReq)+1)
	for key, value := range identityReq {
		req[key] = value
	}
	addJobMetadataRequest(req, metadata)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := postSocket(ctx, socketPath, "/v1/github/host/start", req); err != nil {
		fmt.Fprintf(os.Stderr, "host start: %v\n", err)
		os.Exit(1)
	}
}

func runHostEnd(args []string) {
	fs := flag.NewFlagSet("host end", flag.ExitOnError)
	socketPath := defaultSocketPath
	var identity jobIdentityFlags
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), hostEndUsage)
		fmt.Fprintln(fs.Output())
		printGitHubIdentityEnvHelp(fs.Output())
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Equivalent identity flags:")
		fmt.Fprintln(fs.Output(), "  --provider github")
		fmt.Fprintln(fs.Output(), "        CI provider. GitLab host end is driven by cgroup lifecycle.")
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
		fmt.Fprintln(os.Stderr, hostEndUsage)
		os.Exit(2)
	}
	applyGitHubEnvFallback(&identity)
	if err := requireGitHubProvider(identity, "host end supports only provider github; GitLab host end is handled by cgroup lifecycle"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	req, err := buildHostEndRequest(identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := postGitHubHostEnd(ctx, socketPath, req); err != nil {
		fmt.Fprintln(os.Stderr, formatAgentUnreachable(socketPath,
			"The summary_log for this run cannot be emitted.", err))
		os.Exit(1)
	}
}

func postGitHubHostEnd(ctx context.Context, socketPath string, req map[string]string) error {
	if err := postSocket(ctx, socketPath, "/v1/github/job/health", req); err != nil {
		return fmt.Errorf("job health: %w", err)
	}
	return postSocket(ctx, socketPath, "/v1/github/host/end", req)
}

func buildHostEndRequest(identity jobIdentityFlags) (map[string]string, error) {
	return buildJobIdentityRequest(identity)
}
