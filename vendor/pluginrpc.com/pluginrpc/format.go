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
	"fmt"
	"strings"
)

// Format is the serialization mechanism of the body of Requests, Responses and Specs.
type Format uint32

const (
	// FormatBinary is the binary format.
	FormatBinary Format = 1
	// FormatJSON is the JSON format.
	FormatJSON Format = 2

	minFormat = FormatBinary
	maxFormat = FormatJSON

	formatBinaryString = "binary"
	formatJSONString   = "json"
)

var (
	// AllFormats are all Formsts.
	AllFormats = []Format{
		FormatJSON,
		FormatBinary,
	}
)

// String implements fmt.Stringer.
func (f Format) String() string {
	switch f {
	case FormatBinary:
		return formatBinaryString
	case FormatJSON:
		return formatJSONString
	}
	return fmt.Sprintf("format_%d", f)
}

// FormatForString returns the Format for the given string.
//
// Returns 0 if the Format is unknown or s is empty.
func FormatForString(s string) Format {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case formatBinaryString:
		return FormatBinary
	case formatJSONString:
		return FormatJSON
	default:
		return 0
	}
}

// *** PRIVATE ***

func validateFormat(format Format) error {
	if !isValidFormat(format) {
		return fmt.Errorf("unknown Format: %v", format)
	}
	return nil
}

func isValidFormat(format Format) bool {
	return format >= minFormat && format <= maxFormat
}
