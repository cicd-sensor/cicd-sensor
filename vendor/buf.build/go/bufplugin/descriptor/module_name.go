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

package descriptor

import (
	"fmt"
	"strings"

	descriptorv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/descriptor/v1"
	"buf.build/go/protovalidate"
)

// ModuleName is the fully-qualified name of a module on the Buf Schema Registry.
type ModuleName interface {
	// Registry returns the registry hostname of the module.
	//
	// Always present.
	Registry() string
	// Owner returns the name of the owner of the module, either a user or organization.
	//
	// Always present.
	Owner() string
	// Module returns the name of the module.
	//
	// Always present.
	Module() string
	// String returns the ModuleName in the form registry/owner/module.
	String() string
	// ToProto converts the ModuleName to its Protobuf representation.
	ToProto() *descriptorv1.ModuleName

	isModuleName()
}

// NewModuleName returns a new ModuleName.
func NewModuleName(registry string, owner string, module string) (ModuleName, error) {
	moduleName := newModuleName(registry, owner, module)
	if err := protovalidate.Validate(moduleName.ToProto()); err != nil {
		return nil, fmt.Errorf("invalid module name %q: %w", moduleName.String(), err)
	}
	return moduleName, nil
}

// ParseModuleName parses a ModuleName from a string in the form registry/owner/module.
func ParseModuleName(moduleNameString string) (ModuleName, error) {
	registry, ownerAndModule, ok := strings.Cut(moduleNameString, "/")
	if !ok {
		return nil, fmt.Errorf("invalid module name %q: must be in the form registry/owner/module", moduleNameString)
	}
	owner, module, ok := strings.Cut(ownerAndModule, "/")
	if !ok || strings.Contains(module, "/") {
		return nil, fmt.Errorf("invalid module name %q: must be in the form registry/owner/module", moduleNameString)
	}
	return NewModuleName(registry, owner, module)
}

// ModuleNameForProtoModuleName returns a new ModuleName for the given descriptorv1.ModuleName.
//
// Returns nil if protoModuleName is nil.
func ModuleNameForProtoModuleName(protoModuleName *descriptorv1.ModuleName) ModuleName {
	if protoModuleName == nil {
		return nil
	}
	return newModuleName(
		protoModuleName.GetRegistry(),
		protoModuleName.GetOwner(),
		protoModuleName.GetModule(),
	)
}

// *** PRIVATE ***

type moduleName struct {
	registry string
	owner    string
	module   string
}

func newModuleName(registry string, owner string, module string) *moduleName {
	return &moduleName{
		registry: registry,
		owner:    owner,
		module:   module,
	}
}

func (m *moduleName) Registry() string {
	return m.registry
}

func (m *moduleName) Owner() string {
	return m.owner
}

func (m *moduleName) Module() string {
	return m.module
}

func (m *moduleName) String() string {
	return m.registry + "/" + m.owner + "/" + m.module
}

func (m *moduleName) ToProto() *descriptorv1.ModuleName {
	if m == nil {
		return nil
	}
	return descriptorv1.ModuleName_builder{
		Registry: m.registry,
		Owner:    m.owner,
		Module:   m.module,
	}.Build()
}

func (*moduleName) isModuleName() {}
