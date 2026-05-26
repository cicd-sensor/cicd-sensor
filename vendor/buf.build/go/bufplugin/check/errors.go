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
	"strings"
)

type duplicateRuleIDError struct {
	duplicateIDs []string
}

func newDuplicateRuleIDError(duplicateIDs []string) *duplicateRuleIDError {
	return &duplicateRuleIDError{
		duplicateIDs: duplicateIDs,
	}
}

func (r *duplicateRuleIDError) Error() string {
	if r == nil {
		return ""
	}
	if len(r.duplicateIDs) == 0 {
		return ""
	}
	var sb strings.Builder
	_, _ = sb.WriteString("duplicate rule IDs: ")
	_, _ = sb.WriteString(strings.Join(r.duplicateIDs, ", "))
	return sb.String()
}

type duplicateCategoryIDError struct {
	duplicateIDs []string
}

func newDuplicateCategoryIDError(duplicateIDs []string) *duplicateCategoryIDError {
	return &duplicateCategoryIDError{
		duplicateIDs: duplicateIDs,
	}
}

func (c *duplicateCategoryIDError) Error() string {
	if c == nil {
		return ""
	}
	if len(c.duplicateIDs) == 0 {
		return ""
	}
	var sb strings.Builder
	_, _ = sb.WriteString("duplicate category IDs: ")
	_, _ = sb.WriteString(strings.Join(c.duplicateIDs, ", "))
	return sb.String()
}

type duplicateRuleOrCategoryIDError struct {
	duplicateIDs []string
}

func newDuplicateRuleOrCategoryIDError(duplicateIDs []string) *duplicateRuleOrCategoryIDError {
	return &duplicateRuleOrCategoryIDError{
		duplicateIDs: duplicateIDs,
	}
}

func (o *duplicateRuleOrCategoryIDError) Error() string {
	if o == nil {
		return ""
	}
	if len(o.duplicateIDs) == 0 {
		return ""
	}
	var sb strings.Builder
	_, _ = sb.WriteString("duplicate rule or category IDs: ")
	_, _ = sb.WriteString(strings.Join(o.duplicateIDs, ", "))
	return sb.String()
}

type validateRuleSpecError struct {
	delegate error
}

func newValidateRuleSpecErrorf(format string, args ...any) *validateRuleSpecError {
	return &validateRuleSpecError{
		delegate: fmt.Errorf(format, args...),
	}
}

func wrapValidateRuleSpecError(delegate error) *validateRuleSpecError {
	return &validateRuleSpecError{
		delegate: delegate,
	}
}

func (vr *validateRuleSpecError) Error() string {
	if vr == nil {
		return ""
	}
	if vr.delegate == nil {
		return ""
	}
	var sb strings.Builder
	_, _ = sb.WriteString(`invalid check.RuleSpec: `)
	_, _ = sb.WriteString(vr.delegate.Error())
	return sb.String()
}

func (vr *validateRuleSpecError) Unwrap() error {
	if vr == nil {
		return nil
	}
	return vr.delegate
}

type validateCategorySpecError struct {
	delegate error
}

func newValidateCategorySpecErrorf(format string, args ...any) *validateCategorySpecError {
	return &validateCategorySpecError{
		delegate: fmt.Errorf(format, args...),
	}
}

func wrapValidateCategorySpecError(delegate error) *validateCategorySpecError {
	return &validateCategorySpecError{
		delegate: delegate,
	}
}

func (vr *validateCategorySpecError) Error() string {
	if vr == nil {
		return ""
	}
	if vr.delegate == nil {
		return ""
	}
	var sb strings.Builder
	_, _ = sb.WriteString(`invalid check.CategorySpec: `)
	_, _ = sb.WriteString(vr.delegate.Error())
	return sb.String()
}

func (vr *validateCategorySpecError) Unwrap() error {
	if vr == nil {
		return nil
	}
	return vr.delegate
}

type validateSpecError struct {
	delegate error
}

func newValidateSpecError(message string) *validateSpecError {
	return &validateSpecError{
		delegate: errors.New(message),
	}
}

func wrapValidateSpecError(delegate error) *validateSpecError {
	return &validateSpecError{
		delegate: delegate,
	}
}

func (vr *validateSpecError) Error() string {
	if vr == nil {
		return ""
	}
	if vr.delegate == nil {
		return ""
	}
	var sb strings.Builder
	_, _ = sb.WriteString(`invalid check.Spec: `)
	_, _ = sb.WriteString(vr.delegate.Error())
	return sb.String()
}

func (vr *validateSpecError) Unwrap() error {
	if vr == nil {
		return nil
	}
	return vr.delegate
}
