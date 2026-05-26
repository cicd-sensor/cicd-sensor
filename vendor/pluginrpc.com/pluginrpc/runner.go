// Copyright 2024 Buf Technologies, Inc.
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

package pluginrpc

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"slices"
)

var emptyEnv = []string{"__EMPTY_ENV=1"}

// Runner runs external commands.
//
// Runners should not proxy any environment variables to the commands they run.
type Runner interface {
	// Run runs the external command with the given environment.
	//
	// The environment variables are always cleared before running the command.
	// If no stdin, stdout, or stderr are provided, the equivalent of /dev/null are given to the command.
	// The command is run in the context of the current working directory.
	//
	// If there is an exit error, it is returned as a *ExitError.
	Run(ctx context.Context, env Env) error
}

// NewExecRunner returns a new Runner that uses os/exec to call the given
// external command given by the program name.
func NewExecRunner(programName string, options ...ExecRunnerOption) Runner {
	return newExecRunner(programName, options...)
}

// ExecRunnerOption is an option for a new os/exec Runner.
type ExecRunnerOption func(*execRunnerOptions)

// ExecRunnerWithArgs returns a new ExecRunnerOption that specifies a sub-command to invoke
// on the program.
//
// For example, if the plugin is implemented under the sub-command `foo bar`
// on the program `plug`, specifying ExecRunnerWithArgs("foo", "bar") will result in the
// command `plug foo bar` being invoked as the plugin. In this scenario, all procedures
// and flag will be implemented under this sub-command. In this example,
// `plug foo bar --plugin-spec` should produce the spec.
func ExecRunnerWithArgs(args ...string) ExecRunnerOption {
	return func(execRunnerOptions *execRunnerOptions) {
		execRunnerOptions.args = args
	}
}

// NewServerRunner returns a new Runner that directly calls the server.
//
// This is primarily used for testing.
func NewServerRunner(server Server, _ ...ServerRunnerOption) Runner {
	return newServerRunner(server)
}

// ServerRunnerOption is an option for a new ServerRunner.
type ServerRunnerOption func(*serverRunnerOptions)

// *** PRIVATE ***

type execRunner struct {
	programName     string
	programBaseArgs []string
}

func newExecRunner(programName string, options ...ExecRunnerOption) *execRunner {
	execRunnerOptions := newExecRunnerOptions()
	for _, option := range options {
		option(execRunnerOptions)
	}
	return &execRunner{
		programName:     programName,
		programBaseArgs: execRunnerOptions.args,
	}
}

func (e *execRunner) Run(ctx context.Context, env Env) error {
	cmd := exec.CommandContext(ctx, e.programName, append(slices.Clone(e.programBaseArgs), env.Args...)...)
	// We want to make sure the command has access to no env vars, as the default is the current env.
	cmd.Env = emptyEnv
	// If the user did not specify various stdio, we want to make sure
	// the command has access to no stdio.
	if env.Stdin == nil {
		cmd.Stdin = discardReader{}
	} else {
		cmd.Stdin = env.Stdin
	}
	if env.Stdout == nil {
		cmd.Stdout = io.Discard
	} else {
		cmd.Stdout = env.Stdout
	}
	if env.Stderr == nil {
		cmd.Stderr = io.Discard
	} else {
		cmd.Stderr = env.Stderr
	}
	// The default behavior for dir is what we want already, i.e. the current
	// working directory.

	if err := cmd.Run(); err != nil {
		exitError := &exec.ExitError{}
		if errors.As(err, &exitError) {
			return NewExitError(exitError.ExitCode(), exitError)
		}
		return err
	}
	return nil
}

type serverRunner struct {
	server Server
	errs   []error
}

func newServerRunner(server Server) *serverRunner {
	return &serverRunner{
		server: server,
	}
}

func (s *serverRunner) Run(ctx context.Context, env Env) error {
	if len(s.errs) > 0 {
		return errors.Join(s.errs...)
	}
	// Servers directly return ExitErrors, so this fulfills the contract.
	return s.server.Serve(ctx, env)
}

type discardReader struct{}

func (discardReader) Read([]byte) (int, error) {
	return 0, io.EOF
}

type execRunnerOptions struct {
	args []string
}

func newExecRunnerOptions() *execRunnerOptions {
	return &execRunnerOptions{}
}

type serverRunnerOptions struct{}
