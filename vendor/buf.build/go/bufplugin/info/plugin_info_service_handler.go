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

package info

import (
	"context"

	infov1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/info/v1"
	"buf.build/go/bufplugin/internal/gen/buf/plugin/info/v1/v1pluginrpc"
	"buf.build/go/protovalidate"
)

// NewPluginInfoServiceHandler returns a new v1pluginrpc.PluginInfoServiceHandler for the given Spec.
//
// The Spec will be validated.
func NewPluginInfoServiceHandler(spec *Spec, options ...PluginInfoServiceHandlerOption) (v1pluginrpc.PluginInfoServiceHandler, error) {
	return newPluginInfoServiceHandler(spec, options...)
}

// PluginInfoServiceHandlerOption is an option for PluginInfoServiceHandler.
type PluginInfoServiceHandlerOption func(*pluginInfoServiceHandlerOptions)

// PluginInfoServiceHandlerWithValidator allows overriding the default validator used by the handler.
// By default, [protovalidate.GlobalValidator] is used.
func PluginInfoServiceHandlerWithValidator(validator protovalidate.Validator) PluginInfoServiceHandlerOption {
	return func(options *pluginInfoServiceHandlerOptions) {
		options.validator = validator
	}
}

// *** PRIVATE ***

type pluginInfoServiceHandler struct {
	getPluginInfoResponse *infov1.GetPluginInfoResponse
}

func newPluginInfoServiceHandler(spec *Spec, options ...PluginInfoServiceHandlerOption) (*pluginInfoServiceHandler, error) {
	opts := newPluginInfoServiceHandlerOptions()
	for _, opt := range options {
		opt(opts)
	}
	// Also calls ValidateSpec.
	pluginInfo, err := NewPluginInfoForSpec(spec)
	if err != nil {
		return nil, err
	}
	protoPluginInfo := pluginInfo.toProto()
	getPluginInfoResponse := &infov1.GetPluginInfoResponse{
		PluginInfo: protoPluginInfo,
	}
	validator := opts.validator
	if validator == nil {
		validator = protovalidate.GlobalValidator
	}
	if err := validator.Validate(getPluginInfoResponse); err != nil {
		return nil, err
	}
	return &pluginInfoServiceHandler{
		getPluginInfoResponse: getPluginInfoResponse,
	}, nil
}

func (c *pluginInfoServiceHandler) GetPluginInfo(context.Context, *infov1.GetPluginInfoRequest) (*infov1.GetPluginInfoResponse, error) {
	return c.getPluginInfoResponse, nil
}

type pluginInfoServiceHandlerOptions struct {
	validator protovalidate.Validator
}

func newPluginInfoServiceHandlerOptions() *pluginInfoServiceHandlerOptions {
	return &pluginInfoServiceHandlerOptions{}
}
