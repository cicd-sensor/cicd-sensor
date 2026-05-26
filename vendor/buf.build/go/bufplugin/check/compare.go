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

package check

import (
	"strings"

	"buf.build/go/bufplugin/descriptor"
)

// CompareAnnotations returns -1 if one < two, 1 if one > two, 0 otherwise.
func CompareAnnotations(one Annotation, two Annotation) int {
	if one == nil && two == nil {
		return 0
	}
	if one == nil && two != nil {
		return -1
	}
	if one != nil && two == nil {
		return 1
	}
	if compare := strings.Compare(one.RuleID(), two.RuleID()); compare != 0 {
		return compare
	}

	if compare := descriptor.CompareFileLocations(one.FileLocation(), two.FileLocation()); compare != 0 {
		return compare
	}

	if compare := descriptor.CompareFileLocations(one.AgainstFileLocation(), two.AgainstFileLocation()); compare != 0 {
		return compare
	}
	return strings.Compare(one.Message(), two.Message())
}

// CompareRules returns -1 if one < two, 1 if one > two, 0 otherwise.
func CompareRules(one Rule, two Rule) int {
	if one == nil && two == nil {
		return 0
	}
	if one == nil && two != nil {
		return -1
	}
	if one != nil && two == nil {
		return 1
	}
	return strings.Compare(one.ID(), two.ID())
}

// CompareCategories returns -1 if one < two, 1 if one > two, 0 otherwise.
func CompareCategories(one Category, two Category) int {
	if one == nil && two == nil {
		return 0
	}
	if one == nil && two != nil {
		return -1
	}
	if one != nil && two == nil {
		return 1
	}
	return strings.Compare(one.ID(), two.ID())
}

// *** PRIVATE ***

// compareRuleSpecs returns -1 if one < two, 1 if one > two, 0 otherwise.
func compareRuleSpecs(one *RuleSpec, two *RuleSpec) int {
	if one == nil && two == nil {
		return 0
	}
	if one == nil && two != nil {
		return -1
	}
	if one != nil && two == nil {
		return 1
	}
	return strings.Compare(one.ID, two.ID)
}

// compareCategorySpecs returns -1 if one < two, 1 if one > two, 0 otherwise.
func compareCategorySpecs(one *CategorySpec, two *CategorySpec) int {
	if one == nil && two == nil {
		return 0
	}
	if one == nil && two != nil {
		return -1
	}
	if one != nil && two == nil {
		return 1
	}
	return strings.Compare(one.ID, two.ID)
}
