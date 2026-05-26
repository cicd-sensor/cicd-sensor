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
	"context"
	"fmt"
	"slices"

	checkv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/check/v1"
	"buf.build/go/bufplugin/internal/gen/buf/plugin/check/v1/v1pluginrpc"
	"buf.build/go/bufplugin/internal/pkg/thread"
	"buf.build/go/bufplugin/internal/pkg/xslices"
	"buf.build/go/protovalidate"
	"pluginrpc.com/pluginrpc"
)

const defaultPageSize = 250

// NewCheckServiceHandler returns a new v1pluginrpc.CheckServiceHandler for the given Spec.
//
// The Spec will be validated.
func NewCheckServiceHandler(spec *Spec, options ...CheckServiceHandlerOption) (v1pluginrpc.CheckServiceHandler, error) {
	return newCheckServiceHandler(spec, options...)
}

// CheckServiceHandlerOption is an option for CheckServiceHandler.
type CheckServiceHandlerOption func(*checkServiceHandlerOptions)

// CheckServiceHandlerWithParallelism returns a new CheckServiceHandlerOption that sets the parallelism
// by which Rules will be run.
//
// If this is set to a value >= 1, this many concurrent Rules can be run at the same time.
// A value of 0 indicates the default behavior, which is to use runtime.GOMAXPROCS(0).
//
// A value if < 0 has no effect.
func CheckServiceHandlerWithParallelism(parallelism int) CheckServiceHandlerOption {
	return func(checkServiceHandlerOptions *checkServiceHandlerOptions) {
		if parallelism < 0 {
			parallelism = 0
		}
		checkServiceHandlerOptions.parallelism = parallelism
	}
}

// CheckServiceHandlerWithValidator allows overriding the default validator used by the handler.
// By default, [protovalidate.GlobalValidator] is used.
func CheckServiceHandlerWithValidator(validator protovalidate.Validator) CheckServiceHandlerOption {
	return func(checkServiceHandlerOptions *checkServiceHandlerOptions) {
		checkServiceHandlerOptions.validator = validator
	}
}

// *** PRIVATE ***

type checkServiceHandler struct {
	spec                 *Spec
	parallelism          int
	validator            protovalidate.Validator
	rules                []Rule
	ruleIDToRule         map[string]Rule
	ruleIDToRuleHandler  map[string]RuleHandler
	ruleIDToIndex        map[string]int
	categories           []Category
	categoryIDToCategory map[string]Category
	categoryIDToIndex    map[string]int
}

func newCheckServiceHandler(spec *Spec, options ...CheckServiceHandlerOption) (*checkServiceHandler, error) {
	checkServiceHandlerOptions := newCheckServiceHandlerOptions()
	for _, option := range options {
		option(checkServiceHandlerOptions)
	}
	if err := ValidateSpec(spec); err != nil {
		return nil, err
	}
	categorySpecs := slices.Clone(spec.Categories)
	sortCategorySpecs(categorySpecs)
	categories := make([]Category, len(categorySpecs))
	categoryIDToCategory := make(map[string]Category, len(categorySpecs))
	categoryIDToIndex := make(map[string]int, len(categorySpecs))
	for i, categorySpec := range categorySpecs {
		category, err := categorySpecToCategory(categorySpec)
		if err != nil {
			return nil, err
		}
		id := category.ID()
		// Should never happen after validating the Spec.
		if _, ok := categoryIDToCategory[id]; ok {
			return nil, fmt.Errorf("duplicate Category ID: %q", id)
		}
		categories[i] = category
		categoryIDToCategory[id] = category
		categoryIDToIndex[id] = i
	}
	ruleSpecs := slices.Clone(spec.Rules)
	sortRuleSpecs(ruleSpecs)
	rules := make([]Rule, len(ruleSpecs))
	ruleIDToRuleHandler := make(map[string]RuleHandler, len(ruleSpecs))
	ruleIDToRule := make(map[string]Rule, len(ruleSpecs))
	ruleIDToIndex := make(map[string]int, len(ruleSpecs))
	for i, ruleSpec := range ruleSpecs {
		rule, err := ruleSpecToRule(ruleSpec, categoryIDToCategory)
		if err != nil {
			return nil, err
		}
		id := rule.ID()
		// Should never happen after validating the Spec.
		if _, ok := ruleIDToRule[id]; ok {
			return nil, fmt.Errorf("duplicate Rule ID: %q", id)
		}
		rules[i] = rule
		ruleIDToRuleHandler[id] = ruleSpec.Handler
		ruleIDToRule[id] = rule
		ruleIDToIndex[id] = i
	}
	validator := checkServiceHandlerOptions.validator
	if validator == nil {
		validator = protovalidate.GlobalValidator
	}
	return &checkServiceHandler{
		spec:                 spec,
		parallelism:          checkServiceHandlerOptions.parallelism,
		validator:            validator,
		rules:                rules,
		ruleIDToRuleHandler:  ruleIDToRuleHandler,
		ruleIDToRule:         ruleIDToRule,
		ruleIDToIndex:        ruleIDToIndex,
		categories:           categories,
		categoryIDToCategory: categoryIDToCategory,
		categoryIDToIndex:    categoryIDToIndex,
	}, nil
}

func (c *checkServiceHandler) Check(
	ctx context.Context,
	checkRequest *checkv1.CheckRequest,
) (*checkv1.CheckResponse, error) {
	if err := c.validator.Validate(checkRequest); err != nil {
		return nil, pluginrpc.NewError(pluginrpc.CodeInvalidArgument, err)
	}
	request, err := RequestForProtoRequest(checkRequest)
	if err != nil {
		return nil, err
	}
	if c.spec.Before != nil {
		ctx, request, err = c.spec.Before(ctx, request)
		if err != nil {
			return nil, err
		}
	}
	rules := xslices.Filter(c.rules, func(rule Rule) bool { return rule.Default() })
	if ruleIDs := request.RuleIDs(); len(ruleIDs) > 0 {
		rules = make([]Rule, 0)
		for _, ruleID := range ruleIDs {
			rule, ok := c.ruleIDToRule[ruleID]
			if !ok {
				return nil, pluginrpc.NewErrorf(pluginrpc.CodeInvalidArgument, "unknown rule ID: %q", ruleID)
			}
			rules = append(rules, rule)
		}
	}
	multiResponseWriter, err := newMultiResponseWriter(request)
	if err != nil {
		return nil, err
	}
	if err := thread.Parallelize(
		ctx,
		xslices.Map(
			rules,
			func(rule Rule) func(context.Context) error {
				return func(ctx context.Context) error {
					ruleHandler, ok := c.ruleIDToRuleHandler[rule.ID()]
					if !ok {
						// This should never happen.
						return fmt.Errorf("no RuleHandler for id %q", rule.ID())
					}
					return ruleHandler.Handle(
						ctx,
						multiResponseWriter.newResponseWriter(rule.ID()),
						request,
					)
				}
			},
		),
		thread.WithParallelism(c.parallelism),
	); err != nil {
		return nil, err
	}
	response, err := multiResponseWriter.toResponse()
	if err != nil {
		return nil, err
	}
	checkResponse := response.toProto()
	if err := c.validator.Validate(checkResponse); err != nil {
		return nil, err
	}
	return checkResponse, nil
}

func (c *checkServiceHandler) ListRules(_ context.Context, listRulesRequest *checkv1.ListRulesRequest) (*checkv1.ListRulesResponse, error) {
	if err := c.validator.Validate(listRulesRequest); err != nil {
		return nil, pluginrpc.NewError(pluginrpc.CodeInvalidArgument, err)
	}
	rules, nextPageToken, err := c.getRulesAndNextPageToken(
		int(listRulesRequest.GetPageSize()),
		listRulesRequest.GetPageToken(),
	)
	if err != nil {
		return nil, err
	}
	listRulesResponse := &checkv1.ListRulesResponse{
		NextPageToken: nextPageToken,
		Rules:         xslices.Map(rules, Rule.toProto),
	}
	if err := c.validator.Validate(listRulesResponse); err != nil {
		return nil, err
	}
	return listRulesResponse, nil
}

func (c *checkServiceHandler) ListCategories(_ context.Context, listCategoriesRequest *checkv1.ListCategoriesRequest) (*checkv1.ListCategoriesResponse, error) {
	if err := c.validator.Validate(listCategoriesRequest); err != nil {
		return nil, pluginrpc.NewError(pluginrpc.CodeInvalidArgument, err)
	}
	categories, nextPageToken, err := c.getCategoriesAndNextPageToken(
		int(listCategoriesRequest.GetPageSize()),
		listCategoriesRequest.GetPageToken(),
	)
	if err != nil {
		return nil, err
	}
	listCategoriesResponse := &checkv1.ListCategoriesResponse{
		NextPageToken: nextPageToken,
		Categories:    xslices.Map(categories, Category.toProto),
	}
	if err := c.validator.Validate(listCategoriesResponse); err != nil {
		return nil, err
	}
	return listCategoriesResponse, nil
}

func (c *checkServiceHandler) getRulesAndNextPageToken(pageSize int, pageToken string) ([]Rule, string, error) {
	index := 0
	if pageToken != "" {
		var ok bool
		index, ok = c.ruleIDToIndex[pageToken]
		if !ok {
			return nil, "", pluginrpc.NewErrorf(pluginrpc.CodeInvalidArgument, "unknown page token: %q", pageToken)
		}
	}
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	resultRules := make([]Rule, 0, len(c.rules)-index)
	for range pageSize {
		if index >= len(c.rules) {
			break
		}
		resultRules = append(resultRules, c.rules[index])
		index++
	}
	var nextPageToken string
	if index < len(c.rules) {
		nextPageToken = c.rules[index].ID()
	}
	return resultRules, nextPageToken, nil
}

func (c *checkServiceHandler) getCategoriesAndNextPageToken(pageSize int, pageToken string) ([]Category, string, error) {
	index := 0
	if pageToken != "" {
		var ok bool
		index, ok = c.categoryIDToIndex[pageToken]
		if !ok {
			return nil, "", pluginrpc.NewErrorf(pluginrpc.CodeInvalidArgument, "unknown page token: %q", pageToken)
		}
	}
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	resultCategories := make([]Category, 0, len(c.categories)-index)
	for range pageSize {
		if index >= len(c.categories) {
			break
		}
		resultCategories = append(resultCategories, c.categories[index])
		index++
	}
	var nextPageToken string
	if index < len(c.categories) {
		nextPageToken = c.categories[index].ID()
	}
	return resultCategories, nextPageToken, nil
}

type checkServiceHandlerOptions struct {
	parallelism int
	validator   protovalidate.Validator
}

func newCheckServiceHandlerOptions() *checkServiceHandlerOptions {
	return &checkServiceHandlerOptions{}
}
