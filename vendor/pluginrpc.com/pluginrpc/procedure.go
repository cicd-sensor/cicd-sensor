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
	"net/url"
	"regexp"
	"slices"
	"strings"

	pluginrpcv1 "buf.build/gen/go/pluginrpc/pluginrpc/protocolbuffers/go/pluginrpc/v1"
)

const minProcedureArgLength = 2

var argRegexp = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$`)

// Procedure defines a single procedure that a plugin exposes.
type Procedure interface {
	// Path returns the path of the Procedure.
	//
	// Paths are always valid URIs.
	Path() string
	// Args returns optional custom args which can be used to invoke the Procedure.
	//
	// If there are no args, the Procedure can be invoked with the single arg equal to the path.
	// Arg values may only use the characters [a-zA-Z0-9-_], and never start or end with a dash
	// or underscore.
	Args() []string

	isProcedure()
}

// NewProcedure returns a new validated Procedure for the given path.
func NewProcedure(path string, options ...ProcedureOption) (Procedure, error) {
	return newProcedure(path, options...)
}

// NewProcedureForProto returns a new validated Procedure for the given pluginrpcv1.Procedure.
func NewProcedureForProto(protoProcedure *pluginrpcv1.Procedure) (Procedure, error) {
	return newProcedure(protoProcedure.GetPath(), ProcedureWithArgs(protoProcedure.GetArgs()...))
}

// NewProtoProcedure returns a new pluginrpcv1.Procedure for the given Procedure.
func NewProtoProcedure(procedure Procedure) *pluginrpcv1.Procedure {
	return &pluginrpcv1.Procedure{
		Path: procedure.Path(),
		Args: procedure.Args(),
	}
}

// ProcedureOption is an option for a new Procedure.
type ProcedureOption func(*procedureOptions)

// ProcedureWithArgs specifies optional custom args which can be used to invoke the Procedure.
//
// If there are no args, the Procedure can be invoked with the single arg equal to the path.
// Arg values may only use the characters [a-zA-Z0-9-_], and never start with a dash or underscore.
func ProcedureWithArgs(args ...string) ProcedureOption {
	return func(procedureOptions *procedureOptions) {
		procedureOptions.args = args
	}
}

// *** PRIVATE ***

type procedure struct {
	path string
	args []string
}

func newProcedure(path string, options ...ProcedureOption) (*procedure, error) {
	procedureOptions := newProcedureOptions()
	for _, option := range options {
		option(procedureOptions)
	}
	procedure := &procedure{
		path: path,
		args: procedureOptions.args,
	}
	if err := validateProcedure(procedure); err != nil {
		return nil, err
	}
	return procedure, nil
}

func (p *procedure) Path() string {
	return p.path
}

func (p *procedure) Args() []string {
	return slices.Clone(p.args)
}

func (*procedure) isProcedure() {}

type procedureOptions struct {
	args []string
}

func newProcedureOptions() *procedureOptions {
	return &procedureOptions{}
}

func validateProcedures(procedures []Procedure) error {
	usedPathMap := make(map[string]struct{})
	usedArgsMap := make(map[string]struct{})
	for _, procedure := range procedures {
		path := procedure.Path()
		if _, ok := usedPathMap[path]; ok {
			return fmt.Errorf("duplicate procedure path: %q", path)
		}
		usedPathMap[path] = struct{}{}
		args := procedure.Args()
		if len(args) > 0 {
			// We can do this given that we have a valid Spec where
			// args do not contain spaces.
			joinedArgs := strings.Join(args, " ")
			if _, ok := usedArgsMap[joinedArgs]; ok {
				return fmt.Errorf("duplicate procedure args: %q", joinedArgs)
			}
			usedArgsMap[joinedArgs] = struct{}{}
		}
	}
	return nil
}

func validateProcedure(procedure *procedure) error {
	if procedure.path == "" {
		return errors.New("procedure path is empty")
	}
	if _, err := url.ParseRequestURI(procedure.path); err != nil {
		return fmt.Errorf("invalid procedure path: %w", err)
	}
	for _, arg := range procedure.args {
		if len(arg) < minProcedureArgLength {
			return fmt.Errorf("arg %q for procedure %q must be at least length %d", arg, procedure.path, minProcedureArgLength)
		}
		if !argRegexp.MatchString(arg) {
			return fmt.Errorf("arg %q for procedure %q must only consist of characters [a-zA-Z0-9-_] and cannot start or end with a dash or underscore", arg, procedure.path)
		}
	}
	return nil
}
