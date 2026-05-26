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
	"slices"

	pluginrpcv1 "buf.build/gen/go/pluginrpc/pluginrpc/protocolbuffers/go/pluginrpc/v1"
)

// Spec specifies a set of Procedures that a plugin implements. This describes
// the shape of the plugin to clients.
//
// Specs are returned on stdout when `--spec` is called.
//
// A given Spec will have no duplicate Procedures either by path or args.
type Spec interface {
	// ProcedureForPath returns the Procedure for the given path.
	//
	// If no such procedure exists, this returns nil.
	ProcedureForPath(path string) Procedure
	// Procedures returns all Procedures.
	Procedures() []Procedure

	isSpec()
}

// NewSpec returns a new validated Spec for the given Procedures.
func NewSpec(procedures ...Procedure) (Spec, error) {
	return newSpec(procedures)
}

// NewSpecForProto returns a new validated Spec for the given pluginrpcv1.Spec.
func NewSpecForProto(protoSpec *pluginrpcv1.Spec) (Spec, error) {
	procedures := make([]Procedure, len(protoSpec.GetProcedures()))
	for i, protoProcedure := range protoSpec.GetProcedures() {
		procedure, err := NewProcedureForProto(protoProcedure)
		if err != nil {
			return nil, err
		}
		procedures[i] = procedure
	}
	return NewSpec(procedures...)
}

// NewProtoSpec returns a new pluginrpcv1.Spec for the given Spec.
func NewProtoSpec(spec Spec) *pluginrpcv1.Spec {
	procedures := spec.Procedures()
	protoProcedures := make([]*pluginrpcv1.Procedure, len(procedures))
	for i, procedure := range procedures {
		protoProcedures[i] = NewProtoProcedure(procedure)
	}
	return &pluginrpcv1.Spec{
		Procedures: protoProcedures,
	}
}

// MergeSpecs merges the given Specs.
//
// Returns error if any Procedures overlap by Path or Args.
func MergeSpecs(specs ...Spec) (Spec, error) {
	var procedures []Procedure
	for _, spec := range specs {
		procedures = append(procedures, spec.Procedures()...)
	}
	return NewSpec(procedures...)
}

// *** PRIVATE ***

type spec struct {
	procedures      []Procedure
	pathToProcedure map[string]Procedure
}

func newSpec(procedures []Procedure) (*spec, error) {
	if err := validateProcedures(procedures); err != nil {
		return nil, err
	}
	pathToProcedure := make(map[string]Procedure)
	for _, procedure := range procedures {
		pathToProcedure[procedure.Path()] = procedure
	}
	return &spec{
		procedures:      procedures,
		pathToProcedure: pathToProcedure,
	}, nil
}

func (s *spec) ProcedureForPath(path string) Procedure {
	return s.pathToProcedure[path]
}

func (s *spec) Procedures() []Procedure {
	return slices.Clone(s.procedures)
}

func (*spec) isSpec() {}
