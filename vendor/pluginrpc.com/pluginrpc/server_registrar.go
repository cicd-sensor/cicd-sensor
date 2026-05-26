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
	"sync"
)

// ServerRegistrar is used to registered paths when constructing a server.
//
// By splitting out registration from the Server interface, we allow the Server to be immutable.
//
// Generally, ServerRegistrars are called by `Register.*Server` functions from generated code.
type ServerRegistrar interface {
	// Register registers the given handle function for the given path.
	//
	// Paths must be unique.
	Register(path string, handleFunc func(context.Context, HandleEnv, ...HandleOption) error)

	pathToHandleFunc() (map[string]func(context.Context, HandleEnv, ...HandleOption) error, error)

	isServerRegistrar()
}

// NewServerRegistrar returns a new ServerRegistrar.
func NewServerRegistrar() ServerRegistrar {
	return newServerRegistrar()
}

// *** PRIVATE ***

type serverRegistrar struct {
	pathToHandleFuncMap map[string]func(context.Context, HandleEnv, ...HandleOption) error
	errs                []error
	read                bool
	lock                sync.Mutex
}

func newServerRegistrar() *serverRegistrar {
	return &serverRegistrar{
		pathToHandleFuncMap: make(map[string]func(context.Context, HandleEnv, ...HandleOption) error),
	}
}

func (s *serverRegistrar) Register(path string, handleFunc func(context.Context, HandleEnv, ...HandleOption) error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.read {
		s.errs = append(s.errs, errors.New("server registrar already used"))
		return
	}

	if _, ok := s.pathToHandleFuncMap[path]; ok {
		s.errs = append(s.errs, fmt.Errorf("path %q already registered", path))
		return
	}
	s.pathToHandleFuncMap[path] = handleFunc
}

func (s *serverRegistrar) pathToHandleFunc() (map[string]func(context.Context, HandleEnv, ...HandleOption) error, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.read = true

	if len(s.errs) > 0 {
		return nil, errors.Join(s.errs...)
	}

	return s.pathToHandleFuncMap, nil
}

func (*serverRegistrar) isServerRegistrar() {}
