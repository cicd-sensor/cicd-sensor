// Copyright 2023-2024 Buf Technologies, Inc.
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

package protoyaml

import (
	"bytes"
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"gopkg.in/yaml.v3"
)

// Marshal marshals the given message to YAML.
func Marshal(message proto.Message) ([]byte, error) {
	return MarshalOptions{}.Marshal(message)
}

// MarshalOptions is a configurable YAML format marshaller.
//
// It uses similar options to protojson.MarshalOptions.
type MarshalOptions struct {
	// The number of spaces to indent. Passed to yaml.Encoder.SetIndent.
	// If 0, uses the default indent of yaml.v3.
	Indent int
	// AllowPartial allows messages that have missing required fields to marshal
	// without returning an error.
	AllowPartial bool
	// UseProtoNames uses proto field name instead of lowerCamelCase name in YAML
	// field names.
	UseProtoNames bool
	// UseEnumNumbers emits enum values as numbers.
	UseEnumNumbers bool
	// EmitUnpopulated specifies whether to emit unpopulated fields.
	EmitUnpopulated bool
	// Resolver is used for looking up types when expanding google.protobuf.Any
	// messages. If nil, this defaults to using protoregistry.GlobalTypes.
	Resolver interface {
		protoregistry.ExtensionTypeResolver
		protoregistry.MessageTypeResolver
	}
}

// Marshal marshals the given message to YAML using the options in MarshalOptions.
// Do not depend on the output to be stable across different versions.
func (o MarshalOptions) Marshal(message proto.Message) ([]byte, error) {
	data, err := protojson.MarshalOptions{
		AllowPartial:    o.AllowPartial,
		UseProtoNames:   o.UseProtoNames,
		UseEnumNumbers:  o.UseEnumNumbers,
		EmitUnpopulated: o.EmitUnpopulated,
		Resolver:        o.Resolver,
	}.Marshal(message)
	if err != nil {
		return nil, err
	}
	yamlVal, err := jsonDataToYAML(data)
	if err != nil {
		return nil, err
	}

	// Write the JSON back out as YAML
	buffer := &bytes.Buffer{}
	encoder := yaml.NewEncoder(buffer)
	encoder.SetIndent(o.Indent)
	if err := encoder.Encode(yamlVal); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func jsonDataToYAML(data []byte) (interface{}, error) {
	// YAML unmarshal preserves the order of fields, but is more restrictive than JSON.
	// Prefer it if the data is valid YAML.
	jsonNode := &yaml.Node{}
	if err := yaml.Unmarshal(data, jsonNode); err == nil {
		if jsonNode.Kind == yaml.DocumentNode {
			jsonNode = jsonNode.Content[0]
		}
		clearStyle(jsonNode)
		return jsonNode, nil
	}

	// If the data is not valid YAML (e.g. a string contains control characters),
	// fall back to JSON unmarshal, which loses field order, but is more permissive.
	var jsonValue interface{}
	if err := json.Unmarshal(data, &jsonValue); err != nil {
		return nil, err
	}
	return jsonValue, nil
}

// clearStyle removes all style information from the node and its children.
//
// Without this, the returned YAML will look exactly like the JSON input.
// TODO: Allow yaml style information to be specified in proto.
func clearStyle(node *yaml.Node) {
	node.Style = 0
	for _, child := range node.Content {
		clearStyle(child)
	}
}
