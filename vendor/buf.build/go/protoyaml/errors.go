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
	"fmt"
	"strings"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"buf.build/go/protovalidate"
	"gopkg.in/yaml.v3"
)

// nodeError is an error that occurred while processing a specific yaml.Node.
type nodeError struct {
	Node  *yaml.Node
	Path  string
	line  string
	cause error
}

func (n *nodeError) Unwrap() error {
	return n.cause
}

// DetailedError returns an error message that includes the path and a code snippet, if
// the lines of the source code are provided.
func (n *nodeError) Error() string {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("%s:%d:%d %s\n", n.Path, n.Node.Line, n.Node.Column, n.Unwrap().Error()))
	if n.line != "" {
		lineNum := fmt.Sprintf("%4d", n.Node.Line)
		result.WriteString(fmt.Sprintf("%s | %s\n", lineNum, n.line))
		marker := strings.Repeat(".", n.Node.Column-1) + "^"
		result.WriteString(fmt.Sprintf("%s | %s\n", lineNum, marker))
	}
	return result.String()
}

// violationError is singe validation violation.
type violationError struct {
	Violation *validate.Violation
}

// Error prints the field path, message, and constraint ID.
func (v *violationError) Error() string {
	return protovalidate.FieldPathString(v.Violation.GetField()) + ": " + v.Violation.GetMessage() + " (" + v.Violation.GetRuleId() + ")"
}
