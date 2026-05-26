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
	"fmt"
	"io"
	"os"

	"github.com/mattn/go-isatty"
)

// Handler handles requests on the server side.
//
// This is used within generated code when registering an implementation of a service.
//
// Currently, Handlers do not have any customization, however this type is exposes
// so that customization can be provided in the future.
type Handler interface {
	Handle(
		ctx context.Context,
		handleEnv HandleEnv,
		request any,
		handle func(context.Context, any) (any, error),
		options ...HandleOption,
	) error

	isHandler()
}

// NewHandler returns a new Handler.
func NewHandler(spec Spec, _ ...HandlerOption) Handler {
	return newHandler(spec)
}

// HandlerOption is an option for a new Handler.
type HandlerOption func(*handlerOptions)

// HandleOption is an option for handler.Handle.
type HandleOption func(*handleOptions)

// HandleWithFormat returns a new HandleOption that says to marshal and unmarshal requests,
// responses, and errors in the given format.
//
// The default is FormatBinary.
func HandleWithFormat(format Format) HandleOption {
	return func(handleOptions *handleOptions) {
		handleOptions.format = format
	}
}

// HandleEnv is the part of the environment that Handlers can have access to.
type HandleEnv struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// *** PRIVATE ***

type handler struct {
	spec Spec
}

func newHandler(spec Spec) *handler {
	return &handler{
		spec: spec,
	}
}

func (h *handler) Handle(
	ctx context.Context,
	handleEnv HandleEnv,
	request any,
	handle func(context.Context, any) (any, error),
	options ...HandleOption,
) (retErr error) {
	handleOptions := newHandleOptions()
	for _, option := range options {
		option(handleOptions)
	}
	if err := validateFormat(handleOptions.format); err != nil {
		return err
	}

	defer func() {
		if retErr != nil {
			retErr = h.writeError(handleOptions.format, handleEnv, retErr)
		}
	}()

	data, err := readStdin(handleEnv.Stdin)
	if err != nil {
		return err
	}
	if err := unmarshalRequest(handleOptions.format, data, request); err != nil {
		return err
	}
	response, err := handle(ctx, request)
	if err != nil {
		// TODO: This results in writeError being called, but ignores marshaling
		// the response, so we will never have a non-nil response and non-nil
		// error together, which the protocol says we can have.
		//
		// This just needs some refactoring.
		return err
	}
	data, err = marshalResponse(handleOptions.format, response, nil)
	if err != nil {
		return err
	}
	if _, err = handleEnv.Stdout.Write(data); err != nil {
		return fmt.Errorf("failed to write response to stdout: %w", err)
	}
	return err
}

func (h *handler) writeError(format Format, handleEnv HandleEnv, inputErr error) error {
	if inputErr == nil {
		return nil
	}
	// TODO: Format doesn't matter here, as we don't marshal any response.
	// However, if we fix the above and do marshal responses with errors, it will matter.
	data, err := marshalResponse(format, nil, inputErr)
	if err != nil {
		return err
	}
	if _, err := handleEnv.Stdout.Write(data); err != nil {
		return fmt.Errorf("failed to write error to stdout: %w", err)
	}
	return nil
}

func (*handler) isHandler() {}

// readStdin handles stdin specially to determine if stdin is a *os.File (likely os.Stdin)
// and is itself a terminal. If so, we don't block on io.ReadAll, as we know that there
// is no data in stdin and we can return.
//
// This allows server-side implementations of services to not require i.e.:
//
//	echo '{}' | plugin-server /pkg.Service/Method
//
// Instead allowing to just invoke the following if there is no request data:
//
//	plugin-server /pkg.Service/Method
func readStdin(stdin io.Reader) ([]byte, error) {
	file, ok := stdin.(*os.File)
	if ok {
		if isatty.IsTerminal(file.Fd()) || isatty.IsCygwinTerminal(file.Fd()) {
			// Nothing on stdin
			return nil, nil
		}
	}
	return io.ReadAll(stdin)
}

func handleEnvForEnv(env Env) HandleEnv {
	return HandleEnv{
		Stdin:  env.Stdin,
		Stdout: env.Stdout,
		Stderr: env.Stderr,
	}
}

type handlerOptions struct{}

type handleOptions struct {
	format Format
}

func newHandleOptions() *handleOptions {
	return &handleOptions{
		format: FormatBinary,
	}
}
