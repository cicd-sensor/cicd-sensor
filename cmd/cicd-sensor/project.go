package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/projectconfig"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

const (
	projectUsage       = "usage: cicd-sensor project <start|result> [...]"
	projectStartUsage  = "usage: cicd-sensor project start [flags]"
	projectResultUsage = "usage: cicd-sensor project result [flags]"

	// projectResultResponseMaxBytes bounds the /v1/project/result response
	// the CLI will ingest. It matches the agent-side cap (10 MiB) with a
	// little headroom; cicd-sensorctl renderers consume the body verbatim.
	projectResultResponseMaxBytes = 16 << 20
)

func runProjectSubcommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, projectUsage)
		os.Exit(2)
	}

	switch args[0] {
	case "start":
		runProjectStart(args[1:])
	case "result":
		runProjectResult(args[1:])
	default:
		fmt.Fprintln(os.Stderr, projectUsage)
		os.Exit(2)
	}
}

func runProjectStart(args []string) {
	fs := flag.NewFlagSet("project start", flag.ExitOnError)
	socketPath := defaultSocketPath
	var configFile string
	var rulesFile string
	var managerURL string
	var managerTokenFilePath string
	var debugEnabled bool
	var identity jobIdentityFlags
	var metadata jobMetadataFlags
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), projectStartUsage)
		fmt.Fprintln(fs.Output())
		printGitHubIdentityEnvHelp(fs.Output())
		fmt.Fprintln(fs.Output())
		printGitHubMetadataEnvHelp(fs.Output())
		fmt.Fprintln(fs.Output())
		printRequiredIdentityFlagsHelp(fs.Output(), "CI provider. GitLab project start is Phase 2.")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Conditionally required:")
		fmt.Fprintln(fs.Output(), "  CICD_SENSOR_MANAGER_TOKEN or --manager-token-file PATH")
		fmt.Fprintln(fs.Output(), "        Required only when --manager-url is set.")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Optional:")
		fmt.Fprintf(fs.Output(), "  --socket PATH\n        Agent control socket path. (default %q)\n", defaultSocketPath)
		fmt.Fprintln(fs.Output(), "  --config-file PATH")
		fmt.Fprintln(fs.Output(), "        Path to the project-side config YAML. Cannot be combined with --manager-url.")
		fmt.Fprintln(fs.Output(), "  --rules-file PATH")
		fmt.Fprintln(fs.Output(), "        Path to the project-local rules YAML file.")
		fmt.Fprintln(fs.Output(), "  --manager-url URL")
		fmt.Fprintln(fs.Output(), "        Project scope manager URL. Cannot be combined with --config-file or --rules-file.")
		fmt.Fprintln(fs.Output(), "  --manager-token-file PATH")
		fmt.Fprintln(fs.Output(), "        Path to a file containing the project manager bearer token. Overrides CICD_SENSOR_MANAGER_TOKEN.")
		fmt.Fprintln(fs.Output(), "  --enable-debug")
		fmt.Fprintln(fs.Output(), "        Enable GitHub Actions debug artifact output.")
		fmt.Fprintln(fs.Output())
		printOptionalMetadataFlagsHelp(fs.Output())
	}
	fs.StringVar(&socketPath, "socket", socketPath, "Agent control socket path.")
	registerJobIdentityFlags(fs, &identity)
	registerJobMetadataFlags(fs, &metadata)
	fs.StringVar(&configFile, "config-file", "", "Path to the project-side config file.")
	fs.StringVar(&rulesFile, "rules-file", "", "Path to the project-local rules YAML file.")
	fs.StringVar(&managerURL, "manager-url", "", "Project scope manager URL.")
	fs.StringVar(&managerTokenFilePath, "manager-token-file", "", "Path to a file containing the project manager bearer token.")
	fs.BoolVar(&debugEnabled, "enable-debug", false, "Enable GitHub Actions debug artifact output.")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, projectStartUsage)
		os.Exit(2)
	}
	applyGitHubEnvFallback(&identity)
	applyGitHubMetadataEnvFallback(&metadata)

	if err := requireGitHubProvider(identity, "project start supports only provider github; GitLab project start is Phase 2"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	projectManager, err := buildProjectManagerConnection(managerURL, managerTokenFilePath, slog.Default())
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve manager token: %v\n", err)
		os.Exit(1)
	}

	req, err := buildProjectStartRequest(identity, metadata, configFile, rulesFile, projectManager, debugEnabled)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := postSocket(ctx, socketPath, "/v1/github/project/start", req); err != nil {
		fmt.Fprintf(os.Stderr, "project start: %v\n", err)
		os.Exit(1)
	}
}

func runProjectResult(args []string) {
	fs := flag.NewFlagSet("project result", flag.ExitOnError)
	socketPath := defaultSocketPath
	var outputFile string
	var identity jobIdentityFlags
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), projectResultUsage)
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Required:")
		fmt.Fprintln(fs.Output(), "  --provider github")
		fmt.Fprintln(fs.Output(), "        CI provider. GitLab project result is Phase 2.")
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
		fmt.Fprintln(fs.Output(), "Optional:")
		fmt.Fprintf(fs.Output(), "  --socket PATH\n        Agent control socket path. (default %q)\n", defaultSocketPath)
		fmt.Fprintln(fs.Output(), "  --output-file FILE")
		fmt.Fprintln(fs.Output(), "        File to write the summary_log JSON to. Writes to stdout when empty.")
	}
	fs.StringVar(&socketPath, "socket", socketPath, "Agent control socket path.")
	registerJobIdentityFlags(fs, &identity)
	fs.StringVar(&outputFile, "output-file", "", "File to write the summary_log JSON to (stdout when empty).")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, projectResultUsage)
		os.Exit(2)
	}

	if err := requireGitHubProvider(identity, "project result supports only provider github; GitLab project result is Phase 2"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	req, err := buildJobIdentityRequest(identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	body, err := postSocketForResponse(ctx, socketPath, "/v1/github/project/result", req, projectResultResponseMaxBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "project result: %v\n", err)
		os.Exit(1)
	}

	if err := writeProjectResult(outputFile, body, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "project result: %v\n", err)
		os.Exit(1)
	}
}

func buildProjectManagerConnection(managerURL string, managerTokenFilePath string, logger *slog.Logger) (managerConnectionConfig, error) {
	if managerURL == "" {
		if managerTokenFilePath != "" {
			return managerConnectionConfig{}, fmt.Errorf("--manager-token-file requires --manager-url")
		}
		return managerConnectionConfig{}, nil
	}

	managerToken, err := resolveManagerTokenSecret(managerTokenFilePath, logger)
	if err != nil {
		return managerConnectionConfig{}, err
	}
	return managerConnectionConfig{URL: managerURL, Token: managerToken}, nil
}

func writeProjectResult(outputFile string, body []byte, stdout io.Writer) error {
	if outputFile == "" {
		if _, err := stdout.Write(body); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		return nil
	}

	if err := os.WriteFile(outputFile, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outputFile, err)
	}
	return nil
}

func buildProjectStartRequest(identity jobIdentityFlags, metadata jobMetadataFlags, configFile string, rulesFile string, manager managerConnectionConfig, debugEnabled bool) (map[string]any, error) {
	identityReq, err := buildJobIdentityRequest(identity)
	if err != nil {
		return nil, err
	}

	req := make(map[string]any, len(identityReq)+4)
	for key, value := range identityReq {
		req[key] = value
	}
	addJobMetadataRequest(req, metadata)
	if debugEnabled {
		req["debug_enabled"] = true
	}

	if manager.URL != "" {
		if configFile != "" {
			return nil, fmt.Errorf("project manager cannot be combined with --config-file")
		}
		if rulesFile != "" {
			return nil, fmt.Errorf("project manager cannot be combined with --rules-file")
		}
		if manager.Token == "" {
			return nil, fmt.Errorf("project manager requires CICD_SENSOR_MANAGER_TOKEN env or --manager-token-file")
		}
		req["manager_url"] = manager.URL
		req["manager_token"] = manager.Token
		return req, nil
	}

	if configFile != "" {
		projectConfig, err := projectconfig.Load(configFile)
		if err != nil {
			return nil, err
		}
		if projectConfig.DefaultMaxAlertsPerRule != nil && *projectConfig.DefaultMaxAlertsPerRule != 0 {
			req["default_max_alerts_per_rule"] = *projectConfig.DefaultMaxAlertsPerRule
		}
	}

	if rulesFile != "" {
		loadedRules, err := rulesource.LoadRulesFile(rulesFile)
		if err != nil {
			return nil, err
		}
		req["rule_sources"] = []rulesource.LoadedRules{*loadedRules}
	}

	return req, nil
}
