// Copyright 2024-2025 Buf Technologies, Inc.
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

// Package protoplugin is a simple library to assist in writing protoc plugins.
package protoplugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/pluginpb"
)

var (
	// osEnv is the os-based Env used in Main.
	osEnv = Env{
		Args:    os.Args[1:],
		Environ: os.Environ(),
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
	}
	interruptSignals = append([]os.Signal{os.Interrupt}, extraInterruptSignals...)
)

// Main simplifies the authoring of main functions to invoke Handler.
//
// Main will handle interrupt signals, and exit with a non-zero exit code if the Handler
// returns an error.
//
//	func main() {
//	  protoplugin.Main(newHandler())
//	}
func Main(handler Handler, options ...MainOption) {
	opts := newOpts()
	for _, option := range options {
		option.applyMainOption(opts)
	}
	ctx, cancel := withCancelInterruptSignal(context.Background())
	if err := run(ctx, osEnv, handler, opts); err != nil {
		exitError := &exec.ExitError{}
		if errors.As(err, &exitError) {
			cancel()
			// Swallow error message - it was printed via os.Stderr redirection.
			os.Exit(exitError.ExitCode())
		}
		if errString := err.Error(); errString != "" {
			_, _ = fmt.Fprintln(os.Stderr, errString)
		}
		cancel()
		os.Exit(1)
	}
	cancel()
}

// Run runs the plugin using the Handler for the given environment.
//
// This is the function that Main calls to invoke Handlers. However, Run gives you control over
// the environment, and does not provide additional functionality such as handling interrupts. Run is useful
// when writing plugin tests, or if you want to use your own custom logic for main functions.
func Run(
	ctx context.Context,
	env Env,
	handler Handler,
	options ...RunOption,
) error {
	opts := newOpts()
	for _, option := range options {
		option.applyRunOption(opts)
	}
	return run(ctx, env, handler, opts)
}

// MainOption is an option for Main.
type MainOption interface {
	applyMainOption(opts *opts)
}

// RunOption is an option for Run.
//
// Note that RunOptions are also MainOptions, so all RunOptions can also be passed to Main.
type RunOption interface {
	MainOption

	applyRunOption(opts *opts)
}

// WithVersion returns a new RunOption that will result in the given version string being printed
// to stdout if the plugin is given the --version flag.
//
// This can be passed to Main or Run.
//
// The default is no version flag is installed.
func WithVersion(version string) RunOption {
	return optsFunc(func(opts *opts) {
		opts.version = version
	})
}

// WithLenientValidation returns a new RunOption that says handle non-critical issues
// as warnings that will be handled by the given warning handler.
//
// This allows the following issues to result in warnings instead of errors:
//
//   - Duplicate file names for files without insertion points. If the same file name is used two or more times for
//     files without insertion points, the first occurrence of the file will be used and subsequent occurrences will
//     be dropped.
//   - File names that are not equal to filepath.ToSlash(filepath.Clean(name)). The file name will be modified
//     with this normalization.
//
// These issues result in CodeGeneratorResponses that are not properly formed per the CodeGeneratorResponse
// spec, however both protoc and buf have been resilient to these issues for years. There are numerous plugins
// out in the wild that have these issues, and protoplugin should be able to function as a proxy to these
// plugins without error.
//
// Most users of protoplugin should not use this option, this should only be used for plugins that proxy to other
// plugins. If you are authoring a standalone plugin, you should instead make sure your responses are completely correct.
//
// This option can be passed to Main or Run.
//
// The default is to error on these issues.
//
// Implementers of lenientValidationErrorFunc can assume that errors passed will be non-nil and have non-empty
// values for err.Error().
func WithLenientValidation(lenientValidateErrorFunc func(error)) RunOption {
	return optsFunc(func(opts *opts) {
		opts.lenientValidateErrorFunc = lenientValidateErrorFunc
	})
}

// WithExtensionTypeResolver returns a new RunOption that overrides the default extension resolver when
// unmarshaling Protobuf messages.
func WithExtensionTypeResolver(extensionTypeResolver protoregistry.ExtensionTypeResolver) RunOption {
	return optsFunc(func(opts *opts) {
		opts.extensionTypeResolver = extensionTypeResolver
	})
}

/// *** PRIVATE ***

func run(
	ctx context.Context,
	env Env,
	handler Handler,
	opts *opts,
) error {
	switch len(env.Args) {
	case 0:
	case 1:
		if opts.version != "" && env.Args[0] == "--version" {
			_, err := fmt.Fprintln(env.Stdout, opts.version)
			return err
		}
		return newUnknownArgumentsError(env.Args)
	default:
		return newUnknownArgumentsError(env.Args)
	}

	input, err := io.ReadAll(env.Stdin)
	if err != nil {
		return err
	}
	codeGeneratorRequest := &pluginpb.CodeGeneratorRequest{}
	unmarshalOptions := proto.UnmarshalOptions{Resolver: opts.extensionTypeResolver}
	if err := unmarshalOptions.Unmarshal(input, codeGeneratorRequest); err != nil {
		return err
	}
	request, err := NewRequest(codeGeneratorRequest)
	if err != nil {
		return err
	}
	responseWriter := NewResponseWriter(ResponseWriterWithLenientValidation(opts.lenientValidateErrorFunc))
	if err := handler.Handle(
		ctx,
		PluginEnv{
			Environ: env.Environ,
			Stderr:  env.Stderr,
		},
		responseWriter,
		request,
	); err != nil {
		return err
	}
	codeGeneratorResponse, err := responseWriter.ToCodeGeneratorResponse()
	if err != nil {
		return err
	}
	data, err := proto.Marshal(codeGeneratorResponse)
	if err != nil {
		return err
	}
	_, err = env.Stdout.Write(data)
	return err
}

// withCancelInterruptSignal returns a context that is cancelled if interrupt signals are sent.
func withCancelInterruptSignal(ctx context.Context) (context.Context, context.CancelFunc) {
	interruptSignalC, closer := newInterruptSignalChannel()
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		<-interruptSignalC
		closer()
		cancel()
	}()
	return ctx, cancel
}

// newInterruptSignalChannel returns a new channel for interrupt signals.
//
// Call the returned function to cancel sending to this channel.
func newInterruptSignalChannel() (<-chan os.Signal, func()) {
	signalC := make(chan os.Signal, 1)
	signal.Notify(signalC, interruptSignals...)
	return signalC, func() {
		signal.Stop(signalC)
		close(signalC)
	}
}

type opts struct {
	version                  string
	lenientValidateErrorFunc func(error)
	extensionTypeResolver    protoregistry.ExtensionTypeResolver
}

func newOpts() *opts {
	return &opts{}
}

type optsFunc func(*opts)

func (f optsFunc) applyMainOption(opts *opts) {
	f(opts)
}

func (f optsFunc) applyRunOption(opts *opts) {
	f(opts)
}
