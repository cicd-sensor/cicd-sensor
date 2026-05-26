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
	"fmt"
	"slices"

	"github.com/spf13/pflag"
)

// Server is the server for plugin implementations.
//
// The easiest way to run a server for a plugin is to call ServerMain.
type Server interface {
	// Serve serves the plugin.
	Serve(ctx context.Context, env Env) error

	isServer()
}

// NewServer returns a new Server for a given Spec and ServerRegistrar.
//
// The Spec will be validated against the ServerRegistar to make sure there is a
// 1-1 mapping between Procedures and registered paths.
//
// Once passed to this constructor, the ServerRegistrar can no longer have new
// paths registered to it.
func NewServer(spec Spec, serverRegistrar ServerRegistrar, options ...ServerOption) (Server, error) {
	return newServer(spec, serverRegistrar, options...)
}

// ServerOption is an option for a new Server.
type ServerOption func(*serverOptions)

// ServerWithDoc will attach the given documentation to the server.
//
// This will add ths given docs as a prefix when the flag -h/--help is used.
func ServerWithDoc(doc string) ServerOption {
	return func(serverOptions *serverOptions) {
		serverOptions.doc = doc
	}
}

// *** PRIVATE ***

type server struct {
	spec             Spec
	pathToHandleFunc map[string]func(context.Context, HandleEnv, ...HandleOption) error
	doc              string
}

func newServer(spec Spec, serverRegistrar ServerRegistrar, options ...ServerOption) (*server, error) {
	serverOptions := newServerOptions()
	for _, option := range options {
		option(serverOptions)
	}
	pathToHandleFunc, err := serverRegistrar.pathToHandleFunc()
	if err != nil {
		return nil, err
	}
	for path := range pathToHandleFunc {
		if spec.ProcedureForPath(path) == nil {
			return nil, fmt.Errorf("path %q not contained within spec", path)
		}
	}
	for _, procedure := range spec.Procedures() {
		if _, ok := pathToHandleFunc[procedure.Path()]; !ok {
			return nil, fmt.Errorf("path %q not registered", procedure.Path())
		}
	}
	return &server{
		spec:             spec,
		pathToHandleFunc: pathToHandleFunc,
		doc:              serverOptions.doc,
	}, nil
}

func (s *server) Serve(ctx context.Context, env Env) error {
	flags, args, err := parseFlags(env.Stderr, env.Args, s.spec, s.doc)
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.printProtocol {
		_, err := env.Stdout.Write(marshalProtocol(protocolVersion))
		return err
	}
	if flags.printSpec {
		data, err := marshalSpec(flags.format, NewProtoSpec(s.spec))
		if err != nil {
			return err
		}
		_, err = env.Stdout.Write(data)
		return err
	}
	for _, procedure := range s.spec.Procedures() {
		if slices.Equal(args, []string{procedure.Path()}) {
			handleFunc := s.pathToHandleFunc[procedure.Path()]
			return handleFunc(ctx, handleEnvForEnv(env), HandleWithFormat(flags.format))
		}
		// TODO: Make sure args do not overlap in procedures
		if slices.Equal(args, procedure.Args()) {
			handleFunc := s.pathToHandleFunc[procedure.Path()]
			return handleFunc(ctx, handleEnvForEnv(env), HandleWithFormat(flags.format))
		}
	}
	return fmt.Errorf("args not recognized: %v", args)
}

func (*server) isServer() {}

type serverOptions struct {
	doc string
}

func newServerOptions() *serverOptions {
	return &serverOptions{}
}
