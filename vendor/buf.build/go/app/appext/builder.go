// Copyright 2025-2026 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package appext

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"buf.build/go/app"
	"github.com/spf13/pflag"
)

const (
	debugFlagName     = "debug"
	logFormatFlagName = "log-format"
	timeoutFlagName   = "timeout"
)

type builder struct {
	appName string

	debug     bool
	noWarn    bool
	logFormat string

	timeout time.Duration
	flagSet *pflag.FlagSet

	defaultTimeout time.Duration
	timeoutFlag    bool

	interceptors   []Interceptor
	loggerProvider LoggerProvider
}

func newBuilder(appName string, options ...BuilderOption) *builder {
	builder := &builder{
		appName:        appName,
		loggerProvider: defaultLoggerProvider,
	}
	for _, option := range options {
		option(builder)
	}
	return builder
}

func (b *builder) BindRoot(flagSet *pflag.FlagSet) {
	b.flagSet = flagSet
	flagSet.BoolVar(&b.debug, debugFlagName, false, b.withEnvUsage("Turn on debug logging", debugFlagName))
	flagSet.StringVar(&b.logFormat, logFormatFlagName, "color", b.withEnvUsage("The log format [text,color,json]", logFormatFlagName))
	if b.timeoutFlag {
		flagSet.DurationVar(&b.timeout, timeoutFlagName, b.defaultTimeout, b.withEnvUsage("The duration until timing out, setting it to 0 means no timeout", timeoutFlagName))
	}

	// We do not officially support this flag, this is for testing, where we need warnings turned off.
	flagSet.BoolVar(&b.noWarn, "no-warn", false, "Turn off warn logging")
	_ = flagSet.MarkHidden("no-warn")

	// We used to have this as a global flag, so we still need to not error when it is called.
	var verbose bool
	flagSet.BoolVarP(&verbose, "verbose", "v", false, "")
	_ = flagSet.MarkHidden("verbose")
}

func (b *builder) NewRunFunc(
	f func(context.Context, Container) error,
) func(context.Context, app.Container) error {
	interceptor := chainInterceptors(b.interceptors...)
	return func(ctx context.Context, appContainer app.Container) error {
		if interceptor != nil {
			return b.run(ctx, appContainer, interceptor(f))
		}
		return b.run(ctx, appContainer, f)
	}
}

func (b *builder) run(
	ctx context.Context,
	appContainer app.Container,
	f func(context.Context, Container) error,
) error {
	debug, err := b.boolFlagOrEnv(appContainer, debugFlagName, b.debug)
	if err != nil {
		return err
	}
	logLevel, err := getLogLevel(debug, b.noWarn)
	if err != nil {
		return err
	}
	logFormatString := b.stringFlagOrEnv(appContainer, logFormatFlagName, b.logFormat)
	logFormat, err := ParseLogFormat(logFormatString)
	if err != nil {
		return err
	}
	timeout, err := b.durationFlagOrEnv(appContainer, timeoutFlagName, b.timeout)
	if err != nil {
		return err
	}
	nameContainer, err := newNameContainer(appContainer, b.appName)
	if err != nil {
		return err
	}
	logger, err := b.loggerProvider(nameContainer, logLevel, logFormat)
	if err != nil {
		return err
	}
	container := newContainer(nameContainer, logger, logLevel, logFormat)

	var cancel context.CancelFunc
	if timeout != 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	return f(ctx, container)
}

// withEnvUsage appends the environment variable for the flag to its usage.
func (b *builder) withEnvUsage(usage string, flagName string) string {
	return usage + " (env " + b.envKey(flagName) + ")"
}

// envKey returns the environment variable key for the flag. The key is the app
// name and flag name joined by an underscore, uppercased, with dashes replaced
// by underscores. For example, BUF_LOG_FORMAT for the flag --log-format of the
// app buf.
func (b *builder) envKey(flagName string) string {
	return getAppNameEnvPrefix(b.appName) + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// envValue returns the environment variable value for the flag if the flag
// was bound and not explicitly set, otherwise the empty string.
func (b *builder) envValue(envContainer app.EnvContainer, flagName string) string {
	if b.flagSet == nil {
		return ""
	}
	flag := b.flagSet.Lookup(flagName)
	if flag == nil || flag.Changed {
		return ""
	}
	return envContainer.Env(b.envKey(flagName))
}

func (b *builder) boolFlagOrEnv(envContainer app.EnvContainer, flagName string, flagValue bool) (bool, error) {
	envValue := b.envValue(envContainer, flagName)
	if envValue == "" {
		return flagValue, nil
	}
	value, err := strconv.ParseBool(envValue)
	if err != nil {
		return false, fmt.Errorf("invalid value %q for %s: %w", envValue, b.envKey(flagName), err)
	}
	return value, nil
}

func (b *builder) stringFlagOrEnv(envContainer app.EnvContainer, flagName string, flagValue string) string {
	if envValue := b.envValue(envContainer, flagName); envValue != "" {
		return envValue
	}
	return flagValue
}

func (b *builder) durationFlagOrEnv(envContainer app.EnvContainer, flagName string, flagValue time.Duration) (time.Duration, error) {
	envValue := b.envValue(envContainer, flagName)
	if envValue == "" {
		return flagValue, nil
	}
	value, err := time.ParseDuration(envValue)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q for %s: %w", envValue, b.envKey(flagName), err)
	}
	return value, nil
}

func getLogLevel(debugFlag bool, noWarnFlag bool) (LogLevel, error) {
	if debugFlag && noWarnFlag {
		return 0, errors.New("cannot set both --debug and --no-warn")
	}
	if noWarnFlag {
		return LogLevelError, nil
	}
	if debugFlag {
		return LogLevelDebug, nil
	}
	return LogLevelInfo, nil
}

func defaultLoggerProvider(container NameContainer, logLevel LogLevel, logFormat LogFormat) (*slog.Logger, error) {
	switch logFormat {
	case LogFormatText, LogFormatColor:
		return slog.New(slog.NewTextHandler(container.Stderr(), &slog.HandlerOptions{Level: logLevel.SlogLevel()})), nil
	case LogFormatJSON:
		return slog.New(slog.NewJSONHandler(container.Stderr(), &slog.HandlerOptions{Level: logLevel.SlogLevel()})), nil
	default:
		return nil, fmt.Errorf("unknown appext.LogFormat: %v", logFormat)
	}
}

// chainInterceptors consolidates the given interceptors into one.
// The interceptors are applied in the order they are declared.
func chainInterceptors(interceptors ...Interceptor) Interceptor {
	if len(interceptors) == 0 {
		return nil
	}
	filtered := make([]Interceptor, 0, len(interceptors))
	for _, interceptor := range interceptors {
		if interceptor != nil {
			filtered = append(filtered, interceptor)
		}
	}
	switch len(filtered) {
	case 0:
		return nil
	case 1:
		return filtered[0]
	default:
		first := filtered[0]
		return func(next func(context.Context, Container) error) func(context.Context, Container) error {
			for i := len(filtered) - 1; i > 0; i-- {
				next = filtered[i](next)
			}
			return first(next)
		}
	}
}
