package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/listener"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/slogid"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

const (
	agentUsage      = "usage: cicd-sensor agent start [flags]"
	agentStartUsage = "usage: cicd-sensor agent start [flags]"
)

type agentStartOptions struct {
	Provider      string
	Runner        string
	ManagerURL    string
	ManagerToken  string
	SocketPath    string
	ShutdownGrace time.Duration
}

func runAgentSubcommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, agentUsage)
		os.Exit(2)
	}
	switch args[0] {
	case "start":
		runAgentStart(args)
	default:
		fmt.Fprintln(os.Stderr, agentUsage)
		os.Exit(2)
	}
}

func runAgentStart(args []string) {
	fs := flag.NewFlagSet("agent start", flag.ExitOnError)
	var socketPath string
	var provider string
	var runner string
	var managerURL string
	var managerTokenFilePath string
	var shutdownGrace time.Duration
	socketPath = defaultSocketPath
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), agentStartUsage)
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Required:")
		fmt.Fprintln(fs.Output(), "  --provider github|gitlab")
		fmt.Fprintln(fs.Output(), "        CI provider this host runs.")
		fmt.Fprintln(fs.Output(), "  --runner machine|kubernetes")
		fmt.Fprintln(fs.Output(), "        Runner type.")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Optional:")
		fmt.Fprintf(fs.Output(), "  --socket PATH\n        Agent control socket path. (default %q)\n", defaultSocketPath)
		fmt.Fprintln(fs.Output(), "  --manager-url URL")
		fmt.Fprintln(fs.Output(), "        Host scope manager URL. Required for host/start.")
		fmt.Fprintln(fs.Output(), "  CICD_SENSOR_MANAGER_TOKEN or --manager-token-file PATH")
		fmt.Fprintln(fs.Output(), "        Host scope manager bearer token. Required only when --manager-url is set.")
		fmt.Fprintln(fs.Output(), "  --shutdown-grace DURATION")
		fmt.Fprintln(fs.Output(), "        Best-effort drain window used after SIGTERM. (default 8s)")
	}
	fs.StringVar(&socketPath, "socket", socketPath, "Agent control socket path.")
	fs.StringVar(&provider, "provider", "", "CI provider this host runs (github or gitlab).")
	fs.StringVar(&runner, "runner", "", "Runner type (machine or kubernetes).")
	fs.StringVar(&managerURL, "manager-url", "", "Host scope manager URL.")
	fs.StringVar(&managerTokenFilePath, "manager-token-file", "", "Path to a file containing the host scope manager bearer token. Overrides CICD_SENSOR_MANAGER_TOKEN.")
	fs.DurationVar(&shutdownGrace, "shutdown-grace", 8*time.Second, "Best-effort drain window used after SIGTERM.")
	if err := fs.Parse(args[1:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, agentStartUsage)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := newCLIJSONLogger()
	slog.SetDefault(logger)

	opts := agentStartOptions{
		Provider:      provider,
		Runner:        runner,
		ManagerURL:    managerURL,
		SocketPath:    socketPath,
		ShutdownGrace: shutdownGrace,
	}
	if err := validateAgentStartRequiredOptions(opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	slog.InfoContext(ctx, "agent_started",
		"version", version.Current,
		"socket", opts.SocketPath,
		"provider", opts.Provider,
		"runner", opts.Runner,
	)

	var hostManager managerclient.Connection
	var hostManagerClient *managerclient.ConfigClient
	if opts.ManagerURL != "" {
		managerToken, err := resolveManagerTokenSecret(managerTokenFilePath, logger)
		if err != nil {
			slog.ErrorContext(ctx, "agent_failed", "error", err)
			os.Exit(1)
		}
		opts.ManagerToken = managerToken
		if err := validateAgentStartOptions(opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		hostManager = managerclient.Connection{BaseURL: opts.ManagerURL, Token: opts.ManagerToken}
		hostManagerClient, err = managerclient.NewConfigClient(logger, hostManager)
		if err != nil {
			slog.ErrorContext(ctx, "agent_failed", "error", err)
			os.Exit(1)
		}
		slog.InfoContext(ctx, "host_manager_client_enabled", "manager_url", hostManager.BaseURL)
	} else if managerTokenFilePath != "" {
		fmt.Fprintln(os.Stderr, "--manager-token-file requires --manager-url")
		os.Exit(1)
	}

	a := agent.NewAgent(logger, opts.SocketPath, jobcontext.Provider(opts.Provider), opts.Runner, hostManager, hostManagerClient)
	a.SetShutdownGrace(opts.ShutdownGrace)
	if err := a.Run(ctx); err != nil {
		if errors.Is(err, listener.ErrAlreadyRunning) {
			slog.InfoContext(ctx, "agent_already_running", "socket", opts.SocketPath)
			return
		}
		slog.ErrorContext(ctx, "agent_failed", "error", err)
		os.Exit(1)
	}

	slog.InfoContext(ctx, "agent_stopped")
}

func validateAgentStartOptions(opts agentStartOptions) error {
	if err := validateAgentStartRequiredOptions(opts); err != nil {
		return err
	}
	if opts.ManagerURL == "" {
		return nil
	}
	if opts.ManagerToken == "" {
		return fmt.Errorf("manager token is required: set CICD_SENSOR_MANAGER_TOKEN or --manager-token-file")
	}
	return nil
}

func validateAgentStartRequiredOptions(opts agentStartOptions) error {
	if opts.Provider == "" {
		return fmt.Errorf("provider is required")
	}
	switch opts.Provider {
	case "github", "gitlab":
	default:
		return fmt.Errorf("provider must be github or gitlab")
	}
	if opts.Runner == "" {
		return fmt.Errorf("runner is required")
	}
	switch opts.Runner {
	case "machine", "kubernetes":
	default:
		return fmt.Errorf("runner must be machine or kubernetes")
	}
	if opts.ShutdownGrace <= 0 {
		return fmt.Errorf("shutdown-grace must be positive")
	}
	return nil
}

func newCLIJSONLogger() *slog.Logger {
	return slog.New(slogid.Wrap(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}))).With("component", "cicd-sensor-agent")
}
