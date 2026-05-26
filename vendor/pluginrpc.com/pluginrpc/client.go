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
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	pluginrpcv1 "buf.build/gen/go/pluginrpc/pluginrpc/protocolbuffers/go/pluginrpc/v1"
)

var (
	defaultStderr = io.Discard
)

// Client is a client that calls plugins.
//
// Typically, Clients are not directly invoked. Instead, the generated code for a given
// service will use a Client to call the Procedures that the service specifies.
type Client interface {
	// Spec returns the Spec that the client receives.
	//
	// Clients will cache retrieved protocols and Specs. If it is possible that a plugin will
	// change during the lifetime of a Client, it is the responsibility of the caller to
	// create a new Client. We may change this requirement in the future.
	Spec(ctx context.Context) (Spec, error)
	// Call calls the given Procedure.
	//
	// The request will be sent over stdin, with a response being sent on stdout.
	// The response given will then be populated.
	Call(
		ctx context.Context,
		procedurePath string,
		request any,
		response any,
		options ...CallOption,
	) error

	isClient()
}

// NewClient returns a new Client for the given Runner.
func NewClient(runner Runner, options ...ClientOption) Client {
	return newClient(runner, options...)
}

// ClientOption is an option for a new Client.
type ClientOption func(*clientOptions)

// ClientWithStderr will result in the stderr of the plugin being propagated to the given writer.
//
// The default is to drop stderr.
func ClientWithStderr(stderr io.Writer) ClientOption {
	return func(clientOptions *clientOptions) {
		clientOptions.stderr = stderr
	}
}

// ClientWithFormat will result in the given Format being used for requests
// and responses.
//
// The default is FormatBinary.
func ClientWithFormat(format Format) ClientOption {
	return func(clientOptions *clientOptions) {
		clientOptions.format = format
	}
}

// CallOption is an option for an individual client call.
type CallOption func(*callOptions)

// *** PRIVATE ***

type client struct {
	runner Runner
	stderr io.Writer
	format Format

	spec    Spec
	specErr error
	lock    sync.RWMutex
}

func newClient(
	runner Runner,
	options ...ClientOption,
) *client {
	clientOptions := newClientOptions()
	for _, option := range options {
		option(clientOptions)
	}
	if clientOptions.stderr == nil {
		clientOptions.stderr = defaultStderr
	}
	if clientOptions.format == 0 {
		clientOptions.format = FormatBinary
	}
	return &client{
		runner: runner,
		stderr: clientOptions.stderr,
		format: clientOptions.format,
	}
}

// TODO: Provide ability for Spec to be invalidated via cache invalidate.
//
// One way this could look: A request sends over a "spec ID", which is an ID that is returned when
// getting a spec from a plugin. If the plugin does not currently match this spec ID, an error
// is returned on the response, and the client invalidates the Spec cache, and retries. This will
// be desirable for situations where clients are long-lived, for example in services.
func (c *client) Spec(ctx context.Context) (Spec, error) {
	// Difficult to use sync.OnceValues since we want to use the context for cancellation
	// when passing to the runner. It's awkward if the client constructor took a conteext.
	c.lock.RLock()
	if c.spec != nil || c.specErr != nil {
		c.lock.RUnlock()
		return c.spec, c.specErr
	}
	c.lock.RUnlock()

	c.lock.Lock()
	defer c.lock.Unlock()

	if c.spec != nil || c.specErr != nil {
		return c.spec, c.specErr
	}
	c.spec, c.specErr = c.getSpecUncached(ctx)
	return c.spec, c.specErr
}

func (c *client) Call(
	ctx context.Context,
	procedurePath string,
	request any,
	response any,
	_ ...CallOption,
) error {
	// Could make the constructor return an error and validate this at construction
	// but it seems like a bad ROI for such a simple check.
	if err := validateFormat(c.format); err != nil {
		return err
	}
	spec, err := c.Spec(ctx)
	if err != nil {
		return err
	}
	procedure := spec.ProcedureForPath(procedurePath)
	if procedure == nil {
		return NewErrorf(CodeUnimplemented, "procedure unimplemented: %q", procedurePath)
	}
	data, err := marshalRequest(c.format, request)
	if err != nil {
		return err
	}
	stdin := bytes.NewReader(data)
	stdout := bytes.NewBuffer(nil)
	args := procedure.Args()
	if len(args) == 0 {
		args = []string{procedure.Path()}
	}
	args = append(args, "--"+FormatFlagName, c.format.String())
	if err := c.runner.Run(
		ctx,
		Env{
			Args:   args,
			Stdin:  stdin,
			Stdout: stdout,
			Stderr: c.stderr,
		},
	); err != nil {
		return WrapExitError(err)
	}
	return unmarshalResponse(c.format, stdout.Bytes(), response)
}

func (*client) isClient() {}

func (c *client) getSpecUncached(ctx context.Context) (Spec, error) {
	if err := c.checkProtocolVersion(ctx); err != nil {
		return nil, err
	}
	stdout := bytes.NewBuffer(nil)
	if err := c.runner.Run(
		ctx,
		Env{
			Args:   []string{"--" + SpecFlagName, "--" + FormatFlagName, c.format.String()},
			Stdout: stdout,
			Stderr: c.stderr,
		},
	); err != nil {
		return nil, err
	}
	data := stdout.Bytes()
	if len(data) == 0 {
		return nil, fmt.Errorf("--%s did not return a spec", SpecFlagName)
	}
	protoSpec := &pluginrpcv1.Spec{}
	if err := unmarshalSpec(c.format, data, protoSpec); err != nil {
		return nil, fmt.Errorf("--%s did not return a properly-formed spec: %w", SpecFlagName, err)
	}
	return NewSpecForProto(protoSpec)
}

func (c *client) checkProtocolVersion(ctx context.Context) error {
	version, err := c.getProtocolVersionUncached(ctx)
	if err != nil {
		return err
	}
	if version != protocolVersion {
		return fmt.Errorf("--%s returned unknown protocol version %d", ProtocolFlagName, version)
	}
	return nil
}

func (c *client) getProtocolVersionUncached(ctx context.Context) (int, error) {
	stdout := bytes.NewBuffer(nil)
	if err := c.runner.Run(
		ctx,
		Env{
			Args:   []string{"--" + ProtocolFlagName},
			Stdout: stdout,
			Stderr: c.stderr,
		},
	); err != nil {
		return 0, err
	}
	data := stdout.Bytes()
	if len(data) == 0 {
		return 0, fmt.Errorf("--%s did not return a protocol version", ProtocolFlagName)
	}
	version, err := unmarshalProtocol(data)
	if err != nil {
		return 0, fmt.Errorf("--%s did not return a properly-formed protocol version: %w", ProtocolFlagName, err)
	}
	return version, nil
}

type clientOptions struct {
	stderr io.Writer
	format Format
}

func newClientOptions() *clientOptions {
	return &clientOptions{}
}

type callOptions struct{}
