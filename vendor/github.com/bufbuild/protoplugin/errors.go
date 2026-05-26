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

package protoplugin

import (
	"fmt"
	"strings"
)

// unknownArgumentsError is the error returned if Main or Run are given arguments that are unknown.
//
// The only known argument is --version if WithVersion is specified. If any other argumnt is
// specified to the plugin, or WithVersion is not specified, this error is returned.
type unknownArgumentsError struct {
	args []string
}

func newUnknownArgumentsError(args []string) error {
	return &unknownArgumentsError{args: args}
}

func (a *unknownArgumentsError) Error() string {
	if len(a.args) == 1 {
		return "unknown argument: " + a.args[0]
	}
	return "unknown arguments: " + strings.Join(a.args, " ")
}

// unnormalizedCodeGeneratorResponseFileNameError is the error returned if a
// CodeGeneratorResponse.File.Name is not equal to filepath.ToSlash(filepath.Clean(name)).
//
// This may be printed as a warning instead of returned as an error, as this is recoverable.
type unnormalizedCodeGeneratorResponseFileNameError struct {
	name           string
	normalizedName string
	isWarning      bool
}

func newUnnormalizedCodeGeneratorResponseFileNameError(
	name string,
	normalizedName string,
	isWarning bool,
) *unnormalizedCodeGeneratorResponseFileNameError {
	return &unnormalizedCodeGeneratorResponseFileNameError{
		name:           name,
		normalizedName: normalizedName,
		isWarning:      isWarning,
	}
}

func (u *unnormalizedCodeGeneratorResponseFileNameError) Error() string {
	var warningMessage string
	if u.isWarning {
		warningMessage = ` Generation will continue without error here, but please raise an issue with the maintainer of the plugin and reference https://github.com/protocolbuffers/protobuf/blob/95e6c5b4746dd7474d540ce4fb375e3f79a086f8/src/google/protobuf/compiler/plugin.proto#L122`
	}
	return fmt.Sprintf(
		`path %q is not equal to %q, and therefore does not conform to the Protobuf generation specification. The path must be non-empty, relative, use "/" instead of "\" as the path separator, and not use "." or ".." as part of the path.%s`,
		u.name,
		u.normalizedName,
		warningMessage,
	)
}

// duplicateCodeGeneratorResponseFileNameError is the error returned if a CodeGeneratorResponse
// has duplicate file names.
//
// This may be printed as a warning instead of returned as an error, as this is recoverable.
type duplicateCodeGeneratorResponseFileNameError struct {
	name      string
	isWarning bool
}

func newDuplicateCodeGeneratorResponseFileNameError(
	name string,
	isWarning bool,
) *duplicateCodeGeneratorResponseFileNameError {
	return &duplicateCodeGeneratorResponseFileNameError{
		name:      name,
		isWarning: isWarning,
	}
}

func (d *duplicateCodeGeneratorResponseFileNameError) Error() string {
	var warningMessage string
	if d.isWarning {
		warningMessage = ` Generation will continue without error here and drop the second occurrence of this file, but please raise an issue with the maintainer of the plugin.`
	}
	return fmt.Sprintf("duplicate generated file name %q.%s", d.name, warningMessage)
}
