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
	"errors"
	"fmt"
	"slices"
	"sort"

	checkv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/check/v1"
	"buf.build/go/bufplugin/internal/pkg/xslices"
)

// Category is rule category.
//
// Categories have unique IDs. On the server-side (i.e. the plugin), Categories are created
// by CategorySpecs. Clients can list all available plugin Categories by calling ListCategories.
type Category interface {
	// ID is the ID of the Category.
	//
	// Always present.
	//
	// This uniquely identifies the Category.
	ID() string
	// Purpose is a user-displayable purpose of the category.
	//
	// Always present.
	Purpose() string
	// Deprecated returns whether or not this Category is deprecated.
	//
	// If the Category is deprecated, it may be replaced by zero or more Categories. These will
	// be denoted by ReplacementIDs.
	Deprecated() bool
	// ReplacementIDs returns the IDs of the Categories that replace this Category, if this Category is deprecated.
	//
	// This means that the combination of the Categories specified by ReplacementIDs replace this Category entirely,
	// and this Category is considered equivalent to the AND of the categories specified by ReplacementIDs.
	//
	// This will only be non-empty if Deprecated is true.
	//
	// It is not valid for a deprecated Category to specfiy another deprecated Category as a replacement.
	ReplacementIDs() []string

	toProto() *checkv1.Category

	isCategory()
}

// *** PRIVATE ***

type category struct {
	id             string
	purpose        string
	deprecated     bool
	replacementIDs []string
}

func newCategory(
	id string,
	purpose string,
	deprecated bool,
	replacementIDs []string,
) (*category, error) {
	if id == "" {
		return nil, errors.New("check.Category: ID is empty")
	}
	if purpose == "" {
		return nil, errors.New("check.Category: Purpose is empty")
	}
	if !deprecated && len(replacementIDs) > 0 {
		return nil, fmt.Errorf("check.Category: Deprecated is false but ReplacementIDs %v specified", replacementIDs)
	}
	return &category{
		id:             id,
		purpose:        purpose,
		deprecated:     deprecated,
		replacementIDs: replacementIDs,
	}, nil
}

func (r *category) ID() string {
	return r.id
}

func (r *category) Purpose() string {
	return r.purpose
}

func (r *category) Deprecated() bool {
	return r.deprecated
}

func (r *category) ReplacementIDs() []string {
	return slices.Clone(r.replacementIDs)
}

func (r *category) toProto() *checkv1.Category {
	if r == nil {
		return nil
	}
	return &checkv1.Category{
		Id:             r.id,
		Purpose:        r.purpose,
		Deprecated:     r.deprecated,
		ReplacementIds: r.replacementIDs,
	}
}

func (*category) isCategory() {}

func categoryForProtoCategory(protoCategory *checkv1.Category) (Category, error) {
	return newCategory(
		protoCategory.GetId(),
		protoCategory.GetPurpose(),
		protoCategory.GetDeprecated(),
		protoCategory.GetReplacementIds(),
	)
}

func sortCategories(categories []Category) {
	sort.Slice(categories, func(i int, j int) bool { return CompareCategories(categories[i], categories[j]) < 0 })
}

func validateCategories(categories []Category) error {
	return validateNoDuplicateCategoryIDs(xslices.Map(categories, Category.ID))
}

func validateNoDuplicateCategoryIDs(ids []string) error {
	idToCount := make(map[string]int, len(ids))
	for _, id := range ids {
		idToCount[id]++
	}
	var duplicateIDs []string
	for id, count := range idToCount {
		if count > 1 {
			duplicateIDs = append(duplicateIDs, id)
		}
	}
	if len(duplicateIDs) > 0 {
		sort.Strings(duplicateIDs)
		return newDuplicateCategoryIDError(duplicateIDs)
	}
	return nil
}
