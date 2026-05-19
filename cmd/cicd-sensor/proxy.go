package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/proxy/dockerd"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

const proxyUsage = `usage:
  cicd-sensor proxy dockerd [flags]`

const (
	defaultDockerDaemonSocket = "/run/real-docker.sock"
	defaultDockerProxySocket  = "/run/docker.sock"
)

func runProxySubcommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, proxyUsage)
		os.Exit(2)
	}
	switch args[0] {
	case "dockerd":
		runProxyDockerdSubcommand(args[1:])
	default:
		fmt.Fprintln(os.Stderr, proxyUsage)
		os.Exit(2)
	}
}

func runProxyDockerdSubcommand(args []string) {
	fs := flag.NewFlagSet("proxy dockerd", flag.ExitOnError)
	var opts dockerd.Options
	var providerFlag string
	opts.DockerDaemonSocket = defaultDockerDaemonSocket
	opts.DockerProxySocket = defaultDockerProxySocket
	opts.AgentSocket = defaultSocketPath
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), proxyUsage)
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Required:")
		fmt.Fprintln(fs.Output(), "  --provider github|gitlab")
		fmt.Fprintln(fs.Output(), "        CI provider this host serves. Must match the agent's --provider.")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Optional:")
		fmt.Fprintf(fs.Output(), "  --upstream-socket PATH\n        Path to the real dockerd unix socket. (default %q)\n", defaultDockerDaemonSocket)
		fmt.Fprintf(fs.Output(), "  --listen-socket PATH\n        Path to expose to docker clients. (default %q)\n", defaultDockerProxySocket)
		fmt.Fprintf(fs.Output(), "  --agent-socket PATH\n        Path to the cicd-sensor agent admin socket. (default %q)\n", defaultSocketPath)
	}
	fs.StringVar(&opts.DockerDaemonSocket, "upstream-socket", opts.DockerDaemonSocket, "Path to the real dockerd unix socket.")
	fs.StringVar(&opts.DockerProxySocket, "listen-socket", opts.DockerProxySocket, "Path to expose to docker clients.")
	fs.StringVar(&opts.AgentSocket, "agent-socket", opts.AgentSocket, "Path to the cicd-sensor agent admin socket.")
	fs.StringVar(&providerFlag, "provider", "", "CI provider this host serves (github or gitlab). Must match the agent's --provider.")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, proxyUsage)
		os.Exit(2)
	}

	builtOpts, err := buildDockerdOptions(providerFlag, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "cicd-sensor-docker-proxy")
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := dockerd.Run(ctx, logger, builtOpts); err != nil {
		slog.ErrorContext(ctx, "proxy_failed", "error", err)
		os.Exit(1)
	}
}

func buildDockerdOptions(providerFlag string, opts dockerd.Options) (dockerd.Options, error) {
	if providerFlag == "" {
		return dockerd.Options{}, fmt.Errorf("provider is required")
	}
	opts.Provider = jobcontext.Provider(providerFlag)
	return opts, nil
}
