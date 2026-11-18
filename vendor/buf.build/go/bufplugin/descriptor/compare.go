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
	"cmp"
	"slices"
	"strings"
)

// CompareFileLocations returns -1 if one < two, 1 if one > two, 0 otherwise.
func CompareFileLocations(one FileLocation, two FileLocation) int {
	switch {
	case one == nil && two == nil:
		return 0
	case one == nil:
		return -1
	case two == nil:
		return 1
	}
	if compare := strings.Compare(one.FileDescriptor().ProtoreflectFileDescriptor().Path(), two.FileDescriptor().ProtoreflectFileDescriptor().Path()); compare != 0 {
		return compare
	}
	if compare := cmp.Compare(one.StartLine(), two.StartLine()); compare != 0 {
		return compare
	}
	if compare := cmp.Compare(one.StartColumn(), two.StartColumn()); compare != 0 {
		return compare
	}
	if compare := cmp.Compare(one.EndLine(), two.EndLine()); compare != 0 {
		return compare
	}
	if compare := cmp.Compare(one.EndColumn(), two.EndColumn()); compare != 0 {
		return compare
	}
	if compare := slices.Compare(one.unclonedSourcePath(), two.unclonedSourcePath()); compare != 0 {
		return compare
	}
	if compare := strings.Compare(one.LeadingComments(), two.LeadingComments()); compare != 0 {
		return compare
	}
	if compare := strings.Compare(one.TrailingComments(), two.TrailingComments()); compare != 0 {
		return compare
	}
	return slices.Compare(one.unclonedLeadingDetachedComments(), two.unclonedLeadingDetachedComments())
}
