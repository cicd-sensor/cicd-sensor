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
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const exitCodeInternal = 1

// ExitError is an process exit error with an exit code.
//
// Runners return ExitErrors to indicate the exit code of the process.
type ExitError struct {
	exitCode   int
	underlying error
}

// NewExitError returns a new ExitError.
//
// An ExitError will never have an exit code of 0 when returned from this function.
func NewExitError(exitCode int, underlying error) *ExitError {
	return validateExitError(
		&ExitError{
			exitCode:   exitCode,
			underlying: underlying,
		},
	)
}

// WrapExitError wraps the given error as a *ExitError.
//
// If the given error is nil, this returns nil.
// If the given error is already a *ExitError, this is returned.
//
// An ExitError will never have a exit code of 0 when returned from this function.
func WrapExitError(err error) *ExitError {
	if err == nil {
		return nil
	}
	exitError := &ExitError{}
	if errors.As(err, &exitError) {
		return validateExitError(exitError)
	}
	return NewExitError(exitCodeInternal, err)
}

// ExitCode returns the exit code.
//
// If e is nil, this returns 0.
func (e *ExitError) ExitCode() int {
	if e == nil {
		return 0
	}
	return e.exitCode
}

// Error implements error.
//
// If e is nil, this returns the empty string.
func (e *ExitError) Error() string {
	if e == nil {
		return ""
	}
	var sb strings.Builder
	_, _ = sb.WriteString(`Exited with code `)
	_, _ = sb.WriteString(strconv.Itoa(e.exitCode))
	if e.underlying != nil {
		_, _ = sb.WriteString(`: `)
		_, _ = sb.WriteString(e.underlying.Error())
	}
	return sb.String()
}

// Unwrap implements error.
//
// If e is nil, this returns nil.
func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.underlying
}

// *** PRIVATE ***

func validateExitError(exitError *ExitError) *ExitError {
	if exitError.ExitCode() == 0 {
		return newInvalidCodeExitError(exitError)
	}
	return exitError
}

func newInvalidCodeExitError(exitError *ExitError) *ExitError {
	return &ExitError{
		exitCode:   exitCodeInternal,
		underlying: fmt.Errorf("ExitError created with code %d: %w", exitError.ExitCode(), exitError),
	}
}
