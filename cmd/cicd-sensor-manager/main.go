package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/manager"
	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/slogid"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

const managerUsage = "usage: cicd-sensor-manager [flags]"

type managerStartupOptions struct {
	ConfigFile string
	Tokens     []string
}

type tokenFileFlags []string

func (f *tokenFileFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *tokenFileFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	var configFileFlag string
	var rulesFileFlag string
	var tokenFilePaths tokenFileFlags
	var showVersion bool
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), managerUsage)
		fmt.Fprintln(flag.CommandLine.Output())
		fmt.Fprintln(flag.CommandLine.Output(), "Required:")
		fmt.Fprintln(flag.CommandLine.Output(), "  --config-file PATH or CICD_SENSOR_MANAGER_CONFIG_FILE")
		fmt.Fprintln(flag.CommandLine.Output(), "        Manager startup config YAML.")
		fmt.Fprintln(flag.CommandLine.Output(), "  CICD_SENSOR_MANAGER_TOKEN{,_2} or --manager-token-file PATH")
		fmt.Fprintln(flag.CommandLine.Output(), "        Manager bearer token secret. Provide up to 2 tokens for rotation overlap.")
		fmt.Fprintln(flag.CommandLine.Output())
		fmt.Fprintln(flag.CommandLine.Output(), "Optional:")
		fmt.Fprintln(flag.CommandLine.Output(), "  --version, -v")
		fmt.Fprintln(flag.CommandLine.Output(), "        Print version and exit.")
		fmt.Fprintln(flag.CommandLine.Output(), "  --rules-file PATH or CICD_SENSOR_MANAGER_RULES_FILE")
		fmt.Fprintln(flag.CommandLine.Output(), "        Customer rules YAML file. When omitted, only baseline rules are served.")
	}
	flag.StringVar(&configFileFlag, "config-file", "", "Path to the manager startup config file.")
	flag.StringVar(&rulesFileFlag, "rules-file", "", "Path to the customer rules YAML file (optional).")
	flag.Var(&tokenFilePaths, "manager-token-file", "Path to a file containing a bearer token. May be specified up to twice.")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit.")
	flag.BoolVar(&showVersion, "v", false, "Print version and exit.")
	flag.Parse()
	if showVersion {
		fmt.Fprintln(os.Stdout, version.Current)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := newManagerJSONLogger()
	slog.SetDefault(logger)

	tokens, err := resolveManagerTokenSecrets(tokenFilePaths, logger)
	if err != nil {
		slog.ErrorContext(ctx, "manager_failed", "error", err)
		os.Exit(1)
	}
	configFile := resolveFilePathFromFlagOrEnv(configFileFlag, "CICD_SENSOR_MANAGER_CONFIG_FILE", "manager_config_file", logger)
	rulesFile := resolveFilePathFromFlagOrEnv(rulesFileFlag, "CICD_SENSOR_MANAGER_RULES_FILE", "manager_rules_file", logger)
	opts := managerStartupOptions{
		ConfigFile: configFile,
		Tokens:     tokens,
	}
	if err := validateManagerStartupOptions(opts); err != nil {
		slog.ErrorContext(ctx, "manager_failed", "error", err)
		os.Exit(1)
	}
	startupConfig, err := manager.LoadStartupConfig(opts.ConfigFile)
	if err != nil {
		slog.ErrorContext(ctx, "manager_failed", "error", err)
		os.Exit(1)
	}

	bindAddress := startupConfig.BindAddress()

	if rulesFile == "" {
		slog.InfoContext(ctx, "manager_rules_disabled", "reason", "no --rules-file flag or CICD_SENSOR_MANAGER_RULES_FILE")
	}

	router, err := manager.BuildOutputs(ctx, logger, startupConfig.Sinks, startupConfig.Logs)
	if err != nil {
		slog.ErrorContext(ctx, "manager_failed", "error", err)
		os.Exit(1)
	}
	var outputSettings *managerv1beta1.OutputSettings
	if router != nil {
		outputSettings = router.OutputSettings()
	}
	servedConfig := buildServedConfig(startupConfig, outputSettings)

	slog.InfoContext(ctx, "manager_started",
		"version", version.Current,
		"addr", bindAddress,
		"config_file", opts.ConfigFile,
		"rules_file", rulesFile,
		"transport", "plain-http",
		"transport_note", "TLS must be terminated by upstream load balancer or similar",
	)

	s := manager.NewServer(logger, bindAddress, opts.Tokens, servedConfig, rulesFile, &startupConfig, router)
	if err := s.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.ErrorContext(ctx, "manager_failed", "error", err)
		os.Exit(1)
	}
	slog.InfoContext(ctx, "manager_stopped")
}

func validateManagerStartupOptions(opts managerStartupOptions) error {
	if len(opts.Tokens) == 0 {
		return errors.New("manager token is required: set CICD_SENSOR_MANAGER_TOKEN or --manager-token-file")
	}
	if opts.ConfigFile == "" {
		return errors.New("--config-file or CICD_SENSOR_MANAGER_CONFIG_FILE is required")
	}
	return nil
}

// resolveFilePathFromFlagOrEnv returns flagValue when non-empty; otherwise
// the value of envName. When both are set the flag wins and a warning is
// logged so an operator can spot a stale EnvironmentFile.
func resolveFilePathFromFlagOrEnv(flagValue, envName, logKey string, logger *slog.Logger) string {
	if logger == nil {
		logger = slog.Default()
	}
	if flagValue != "" {
		if os.Getenv(envName) != "" {
			logger.Warn(logKey+"_both_sources_specified",
				"preferred", "flag",
				"ignored", envName,
			)
		}
		return flagValue
	}
	return os.Getenv(envName)
}

func resolveManagerTokenSecrets(tokenFiles []string, logger *slog.Logger) ([]string, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(tokenFiles) > 2 {
		return nil, errors.New("--manager-token-file may be specified at most twice")
	}

	var tokens []string
	if len(tokenFiles) > 0 {
		if os.Getenv("CICD_SENSOR_MANAGER_TOKEN") != "" || os.Getenv("CICD_SENSOR_MANAGER_TOKEN_2") != "" {
			logger.Warn("manager_token_both_sources_specified",
				"preferred", "manager-token-file",
				"ignored", "CICD_SENSOR_MANAGER_TOKEN env values",
			)
		}
		for _, path := range tokenFiles {
			token, err := readManagerTokenFile(path)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token)
		}
	} else {
		if token := os.Getenv("CICD_SENSOR_MANAGER_TOKEN"); token != "" {
			tokens = append(tokens, token)
		}
		if token := os.Getenv("CICD_SENSOR_MANAGER_TOKEN_2"); token != "" {
			tokens = append(tokens, token)
		}
	}

	for _, token := range tokens {
		if !managerauth.IsValidToken(token) {
			return nil, errors.New(managerauth.ValidTokenDescription())
		}
	}
	return tokens, nil
}

func readManagerTokenFile(path string) (string, error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", fmt.Errorf("open manager token root %q: %w", dir, err)
	}
	defer root.Close()

	file, err := root.Open(name)
	if err != nil {
		return "", fmt.Errorf("open manager token file %q: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("read manager token file %q: %w", path, err)
	}
	return strings.TrimRight(string(data), "\n"), nil
}

func buildServedConfig(startup manager.StartupConfig, outputSettings *managerv1beta1.OutputSettings) *manager.ServedConfig {
	return &manager.ServedConfig{
		ConfigRevision:          startup.Revision,
		DefaultMaxAlertsPerRule: startup.DefaultMaxAlertsPerRule,
		DisableBaselineRules:    startup.DisableBaselineRules,
		OutputSettings:          outputSettings,
	}
}

func newManagerJSONLogger() *slog.Logger {
	return slog.New(slogid.Wrap(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}))).With("component", "cicd-sensor-manager")
}
