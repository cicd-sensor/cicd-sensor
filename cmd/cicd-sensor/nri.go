package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	nriobserver "github.com/cicd-sensor/cicd-sensor/internal/agent/nri"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

const nriUsage = "usage: cicd-sensor nri [flags]"

type nriOptions struct {
	NRISocket   string
	AgentSocket string
	Provider    string
}

func runNRISubcommand(args []string) {
	fs := flag.NewFlagSet("nri", flag.ExitOnError)
	opts := nriOptions{
		NRISocket:   envOrDefault("CICD_SENSOR_NRI_SOCKET", nriobserver.DefaultSocketPath),
		AgentSocket: envOrDefault("CICD_SENSOR_AGENT_SOCKET", defaultSocketPath),
		Provider:    os.Getenv("CICD_SENSOR_NRI_PROVIDER"),
	}
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), nriUsage)
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Required:")
		fmt.Fprintln(fs.Output(), "  --provider PROVIDER\n        CI/CD provider to observe: github or gitlab. (or CICD_SENSOR_NRI_PROVIDER)")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Optional:")
		fmt.Fprintf(fs.Output(), "  --nri-socket PATH\n        containerd NRI socket path. (default %q)\n", nriobserver.DefaultSocketPath)
		fmt.Fprintf(fs.Output(), "  --agent-socket PATH\n        cicd-sensor agent control socket path. (default %q)\n", defaultSocketPath)
	}
	fs.StringVar(&opts.Provider, "provider", opts.Provider, "CI/CD provider to observe: github or gitlab.")
	fs.StringVar(&opts.NRISocket, "nri-socket", opts.NRISocket, "containerd NRI socket path.")
	fs.StringVar(&opts.AgentSocket, "agent-socket", opts.AgentSocket, "cicd-sensor agent control socket path.")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, nriUsage)
		os.Exit(2)
	}

	runOpts, err := buildNRIObserverOptions(opts, newCLIJSONLogger())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.SetDefault(runOpts.Logger)

	if err := nriobserver.Run(ctx, runOpts); err != nil {
		slog.ErrorContext(ctx, "nri_failed", "error", err)
		os.Exit(1)
	}
}

func buildNRIObserverOptions(opts nriOptions, logger *slog.Logger) (nriobserver.Options, error) {
	runOpts := nriobserver.Options{
		SocketPath:      opts.NRISocket,
		AgentSocketPath: opts.AgentSocket,
		Provider:        jobcontext.Provider(opts.Provider),
		Logger:          logger,
	}
	if err := nriobserver.ValidateOptions(runOpts); err != nil {
		return nriobserver.Options{}, err
	}
	return runOpts, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
