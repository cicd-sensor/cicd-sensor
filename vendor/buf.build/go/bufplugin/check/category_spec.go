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
	"sort"

	"buf.build/go/bufplugin/internal/pkg/xslices"
)

// CategorySpec is the spec for a Category.
//
// It is used to construct a Category on the server-side (i.e. within the plugin). It specifies the
// ID, purpose,  and a CategoryHandler to actually run the Category logic.
//
// Generally, these are provided to Main. This library will handle Check and ListCategories calls
// based on the provided CategorySpecs.
type CategorySpec struct {
	// Required.
	ID string
	// Required.
	Purpose        string
	Deprecated     bool
	ReplacementIDs []string
}

// *** PRIVATE ***

// Assumes that the CategorySpec is validated.
func categorySpecToCategory(categorySpec *CategorySpec) (Category, error) {
	return newCategory(
		categorySpec.ID,
		categorySpec.Purpose,
		categorySpec.Deprecated,
		categorySpec.ReplacementIDs,
	)
}

func validateCategorySpecs(
	categorySpecs []*CategorySpec,
	ruleSpecs []*RuleSpec,
) error {
	categoryIDs := xslices.Map(categorySpecs, func(categorySpec *CategorySpec) string { return categorySpec.ID })
	if err := validateNoDuplicateCategoryIDs(categoryIDs); err != nil {
		return err
	}
	categoryIDForRulesMap := make(map[string]struct{})
	for _, ruleSpec := range ruleSpecs {
		for _, categoryID := range ruleSpec.CategoryIDs {
			categoryIDForRulesMap[categoryID] = struct{}{}
		}
	}
	categoryIDToCategorySpec := make(map[string]*CategorySpec)
	for _, categorySpec := range categorySpecs {
		if err := validateID(categorySpec.ID); err != nil {
			return wrapValidateCategorySpecError(err)
		}
		categoryIDToCategorySpec[categorySpec.ID] = categorySpec
	}
	for _, categorySpec := range categorySpecs {
		if err := validatePurpose(categorySpec.ID, categorySpec.Purpose); err != nil {
			return wrapValidateCategorySpecError(err)
		}
		if len(categorySpec.ReplacementIDs) > 0 && !categorySpec.Deprecated {
			return newValidateCategorySpecErrorf("ID %q had ReplacementIDs but Deprecated was false", categorySpec.ID)
		}
		for _, replacementID := range categorySpec.ReplacementIDs {
			replacementCategorySpec, ok := categoryIDToCategorySpec[replacementID]
			if !ok {
				return newValidateCategorySpecErrorf("ID %q specified replacement ID %q which was not found", categorySpec.ID, replacementID)
			}
			if replacementCategorySpec.Deprecated {
				return newValidateCategorySpecErrorf("Deprecated ID %q specified replacement ID %q which also deprecated", categorySpec.ID, replacementID)
			}
		}
		if _, ok := categoryIDForRulesMap[categorySpec.ID]; !ok {
			return newValidateCategorySpecErrorf("no Rule has a Category ID of %q", categorySpec.ID)
		}
	}
	return nil
}

func sortCategorySpecs(categorySpecs []*CategorySpec) {
	sort.Slice(
		categorySpecs,
		func(i int, j int) bool {
			return compareCategorySpecs(categorySpecs[i], categorySpecs[j]) < 0
		},
	)
}
