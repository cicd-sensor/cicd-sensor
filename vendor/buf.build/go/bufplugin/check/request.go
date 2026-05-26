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
	"fmt"
	"slices"
	"sort"

	checkv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/check/v1"
	"buf.build/go/bufplugin/descriptor"
	"buf.build/go/bufplugin/internal/pkg/xslices"
	"buf.build/go/bufplugin/option"
)

const checkRuleIDPageSize = 250

// Request is a request to a plugin to run checks.
type Request interface {
	// FileDescriptors contains the FileDescriptors to check.
	//
	// Will never be nil or empty.
	//
	// FileDescriptors are guaranteed to be unique with respect to their name.
	FileDescriptors() []descriptor.FileDescriptor
	// AgainstFileDescriptors contains the FileDescriptors to check against, in the
	// case of breaking change plugins.
	//
	// May be empty, including in the case where we did actually specify against
	// FileDescriptors.
	//
	// FileDescriptors are guaranteed to be unique with respect to their name.
	AgainstFileDescriptors() []descriptor.FileDescriptor
	// Options contains any options passed to the plugin.
	//
	// Will never be nil, but may have no values.
	Options() option.Options
	// RuleIDs returns the specific IDs the of Rules to use.
	//
	// If empty, all default Rules will be used.
	// The returned RuleIDs will be sorted.
	//
	// This may return more than 250 IDs; the underlying Client implemention is required to do
	// any necessary chunking.
	//
	// RuleHandlers can safely ignore this - the handling of RuleIDs will have already
	// been performed prior to the Request reaching the RuleHandler.
	RuleIDs() []string

	// toProtos converts the Request into one or more CheckRequests.
	//
	// If there are more than 250 Rule IDs, multiple CheckRequests will be produced by chunking up
	// the Rule IDs.
	toProtos() ([]*checkv1.CheckRequest, error)

	isRequest()
}

// NewRequest returns a new Request for the given FileDescriptors.
//
// FileDescriptors are always required. To set against FileDescriptors or options, use
// WithAgainstFileDescriptors and WithOption.
func NewRequest(
	fileDescriptors []descriptor.FileDescriptor,
	options ...RequestOption,
) (Request, error) {
	return newRequest(fileDescriptors, options...)
}

// RequestOption is an option for a new Request.
type RequestOption func(*requestOptions)

// WithAgainstFileDescriptors adds the given against FileDescriptors to the Request.
func WithAgainstFileDescriptors(againstFileDescriptors []descriptor.FileDescriptor) RequestOption {
	return func(requestOptions *requestOptions) {
		requestOptions.againstFileDescriptors = againstFileDescriptors
	}
}

// WithOptions adds the given Options to the Request.
func WithOptions(options option.Options) RequestOption {
	return func(requestOptions *requestOptions) {
		requestOptions.options = options
	}
}

// WithRuleIDs specifies that the given rule IDs should be used on the Request.
//
// Multiple calls to WithRuleIDs will result in the new rule IDs being appended.
// If duplicate rule IDs are specified, this will result in an error.
func WithRuleIDs(ruleIDs ...string) RequestOption {
	return func(requestOptions *requestOptions) {
		requestOptions.ruleIDs = append(requestOptions.ruleIDs, ruleIDs...)
	}
}

// RequestForProtoRequest returns a new Request for the given checkv1.Request.
func RequestForProtoRequest(protoRequest *checkv1.CheckRequest) (Request, error) {
	fileDescriptors, err := descriptor.FileDescriptorsForProtoFileDescriptors(protoRequest.GetFileDescriptors())
	if err != nil {
		return nil, err
	}
	againstFileDescriptors, err := descriptor.FileDescriptorsForProtoFileDescriptors(protoRequest.GetAgainstFileDescriptors())
	if err != nil {
		return nil, err
	}
	options, err := option.OptionsForProtoOptions(protoRequest.GetOptions())
	if err != nil {
		return nil, err
	}
	return NewRequest(
		fileDescriptors,
		WithAgainstFileDescriptors(againstFileDescriptors),
		WithOptions(options),
		WithRuleIDs(protoRequest.GetRuleIds()...),
	)
}

// *** PRIVATE ***

type request struct {
	fileDescriptors        []descriptor.FileDescriptor
	againstFileDescriptors []descriptor.FileDescriptor
	options                option.Options
	ruleIDs                []string
}

func newRequest(
	fileDescriptors []descriptor.FileDescriptor,
	options ...RequestOption,
) (*request, error) {
	requestOptions := newRequestOptions()
	for _, option := range options {
		option(requestOptions)
	}
	if requestOptions.options == nil {
		requestOptions.options = option.EmptyOptions
	}
	if err := validateNoDuplicateRuleOrCategoryIDs(requestOptions.ruleIDs); err != nil {
		return nil, err
	}
	sort.Strings(requestOptions.ruleIDs)
	if err := validateFileDescriptors(fileDescriptors); err != nil {
		return nil, err
	}
	if err := validateFileDescriptors(requestOptions.againstFileDescriptors); err != nil {
		return nil, err
	}
	return &request{
		fileDescriptors:        fileDescriptors,
		againstFileDescriptors: requestOptions.againstFileDescriptors,
		options:                requestOptions.options,
		ruleIDs:                requestOptions.ruleIDs,
	}, nil
}

func (r *request) FileDescriptors() []descriptor.FileDescriptor {
	return slices.Clone(r.fileDescriptors)
}

func (r *request) AgainstFileDescriptors() []descriptor.FileDescriptor {
	return slices.Clone(r.againstFileDescriptors)
}

func (r *request) Options() option.Options {
	return r.options
}

func (r *request) RuleIDs() []string {
	return slices.Clone(r.ruleIDs)
}

func (r *request) toProtos() ([]*checkv1.CheckRequest, error) {
	if r == nil {
		return nil, nil
	}
	protoFileDescriptors := xslices.Map(r.fileDescriptors, descriptor.FileDescriptor.ToProto)
	protoAgainstFileDescriptors := xslices.Map(r.againstFileDescriptors, descriptor.FileDescriptor.ToProto)
	protoOptions, err := r.options.ToProto()
	if err != nil {
		return nil, err
	}
	if len(r.ruleIDs) == 0 {
		return []*checkv1.CheckRequest{
			{
				FileDescriptors:        protoFileDescriptors,
				AgainstFileDescriptors: protoAgainstFileDescriptors,
				Options:                protoOptions,
			},
		}, nil
	}
	var checkRequests []*checkv1.CheckRequest
	for i := 0; i < len(r.ruleIDs); i += checkRuleIDPageSize {
		start := i
		end := min(start+checkRuleIDPageSize, len(r.ruleIDs))
		checkRequests = append(
			checkRequests,
			&checkv1.CheckRequest{
				FileDescriptors:        protoFileDescriptors,
				AgainstFileDescriptors: protoAgainstFileDescriptors,
				Options:                protoOptions,
				RuleIds:                r.ruleIDs[start:end],
			},
		)
	}
	return checkRequests, nil
}

func (*request) isRequest() {}

func validateFileDescriptors(fileDescriptors []descriptor.FileDescriptor) error {
	_, err := fileNameToFileDescriptorForFileDescriptors(fileDescriptors)
	return err
}

func fileNameToFileDescriptorForFileDescriptors(fileDescriptors []descriptor.FileDescriptor) (map[string]descriptor.FileDescriptor, error) {
	fileNameToFileDescriptor := make(map[string]descriptor.FileDescriptor, len(fileDescriptors))
	for _, fileDescriptor := range fileDescriptors {
		fileName := fileDescriptor.ProtoreflectFileDescriptor().Path()
		if _, ok := fileNameToFileDescriptor[fileName]; ok {
			return nil, fmt.Errorf("duplicate file name: %q", fileName)
		}
		fileNameToFileDescriptor[fileName] = fileDescriptor
	}
	return fileNameToFileDescriptor, nil
}

type requestOptions struct {
	againstFileDescriptors []descriptor.FileDescriptor
	options                option.Options
	ruleIDs                []string
}

func newRequestOptions() *requestOptions {
	return &requestOptions{}
}
