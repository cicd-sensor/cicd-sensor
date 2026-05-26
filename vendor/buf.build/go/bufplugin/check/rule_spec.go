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
	"regexp"
	"sort"

	"buf.build/go/bufplugin/internal/pkg/xslices"
)

const (
	idMinLen = 3
	idMaxLen = 64
)

var (
	idRegexp      = regexp.MustCompile("^[A-Z0-9][A-Z0-9_]*[A-Z0-9]$")
	purposeRegexp = regexp.MustCompile("^[A-Z].*[.]$")
)

// RuleSpec is the spec for a Rule.
//
// It is used to construct a Rule on the server-side (i.e. within the plugin). It specifies the
// ID, categories, purpose, type, and a RuleHandler to actually run the Rule logic.
//
// Generally, these are provided to Main. This library will handle Check and ListRules calls
// based on the provided RuleSpecs.
type RuleSpec struct {
	// Required.
	ID          string
	CategoryIDs []string
	Default     bool
	// Required.
	Purpose string
	// Required.
	Type           RuleType
	Deprecated     bool
	ReplacementIDs []string
	// Required.
	Handler RuleHandler
}

// *** PRIVATE ***

// Assumes that the RuleSpec is validated.
func ruleSpecToRule(ruleSpec *RuleSpec, idToCategory map[string]Category) (Rule, error) {
	categories, err := xslices.MapError(
		ruleSpec.CategoryIDs,
		func(id string) (Category, error) {
			category, ok := idToCategory[id]
			if !ok {
				return nil, fmt.Errorf("no category for id %q", id)
			}
			return category, nil
		},
	)
	if err != nil {
		return nil, err
	}
	return newRule(
		ruleSpec.ID,
		categories,
		ruleSpec.Default,
		ruleSpec.Purpose,
		ruleSpec.Type,
		ruleSpec.Deprecated,
		ruleSpec.ReplacementIDs,
	)
}

func validateRuleSpecs(
	ruleSpecs []*RuleSpec,
	categoryIDMap map[string]struct{},
) error {
	ruleIDs := xslices.Map(ruleSpecs, func(ruleSpec *RuleSpec) string { return ruleSpec.ID })
	if err := validateNoDuplicateRuleIDs(ruleIDs); err != nil {
		return err
	}
	ruleIDToRuleSpec := make(map[string]*RuleSpec)
	for _, ruleSpec := range ruleSpecs {
		if err := validateID(ruleSpec.ID); err != nil {
			return wrapValidateRuleSpecError(err)
		}
		ruleIDToRuleSpec[ruleSpec.ID] = ruleSpec
	}
	for _, ruleSpec := range ruleSpecs {
		for _, categoryID := range ruleSpec.CategoryIDs {
			if _, ok := categoryIDMap[categoryID]; !ok {
				return newValidateRuleSpecErrorf("no category has ID %q", categoryID)
			}
		}
		if err := validatePurpose(ruleSpec.ID, ruleSpec.Purpose); err != nil {
			return wrapValidateRuleSpecError(err)
		}
		if ruleSpec.Type == 0 {
			return newValidateRuleSpecErrorf("Type is not set for ID %q", ruleSpec.ID)
		}
		if _, ok := ruleTypeToProtoRuleType[ruleSpec.Type]; !ok {
			return newValidateRuleSpecErrorf("Type is unknown: %q", ruleSpec.Type)
		}
		if ruleSpec.Handler == nil {
			return newValidateRuleSpecErrorf("Handler is not set for ID %q", ruleSpec.ID)
		}
		if ruleSpec.Default && ruleSpec.Deprecated {
			return newValidateRuleSpecErrorf("ID %q was a default Rule but Deprecated was false", ruleSpec.ID)
		}
		if len(ruleSpec.ReplacementIDs) > 0 && !ruleSpec.Deprecated {
			return newValidateRuleSpecErrorf("ID %q had ReplacementIDs but Deprecated was false", ruleSpec.ID)
		}
		for _, replacementID := range ruleSpec.ReplacementIDs {
			replacementRuleSpec, ok := ruleIDToRuleSpec[replacementID]
			if !ok {
				return newValidateRuleSpecErrorf("ID %q specified replacement ID %q which was not found", ruleSpec.ID, replacementID)
			}
			if replacementRuleSpec.Deprecated {
				return newValidateRuleSpecErrorf("Deprecated ID %q specified replacement ID %q which also deprecated", ruleSpec.ID, replacementID)
			}
		}
	}
	return nil
}

func sortRuleSpecs(ruleSpecs []*RuleSpec) {
	sort.Slice(ruleSpecs, func(i int, j int) bool { return compareRuleSpecs(ruleSpecs[i], ruleSpecs[j]) < 0 })
}

func validateID(id string) error {
	if id == "" {
		return errors.New("ID is empty")
	}
	if len(id) < idMinLen {
		return fmt.Errorf("ID %q must be at least length %d", id, idMinLen)
	}
	if len(id) > idMaxLen {
		return fmt.Errorf("ID %q must be at most length %d", id, idMaxLen)
	}
	if !idRegexp.MatchString(id) {
		return fmt.Errorf("ID %q does not match %q", id, idRegexp.String())
	}
	return nil
}

func validatePurpose(id string, purpose string) error {
	if purpose == "" {
		return fmt.Errorf("Purpose is empty for ID %q", id)
	}
	if !purposeRegexp.MatchString(purpose) {
		return fmt.Errorf("Purpose %q for ID %q does not match %q", purpose, id, purposeRegexp.String())
	}
	return nil
}
