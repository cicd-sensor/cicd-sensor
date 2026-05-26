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
	"buf.build/go/bufplugin/internal/pkg/cache"
	"pluginrpc.com/pluginrpc"
)

// Client is a client for plugin information.
//
// All calls with pluginrpc.Error with CodeUnimplemented if any procedure is not implemented.
type Client interface {
	// GetPluginInfo gets plugin information.
	GetPluginInfo(ctx context.Context, options ...GetPluginInfoCallOption) (PluginInfo, error)

	isClient()
}

// NewClient returns a new Client for the given pluginrpc.Client.
func NewClient(pluginrpcClient pluginrpc.Client, options ...ClientOption) Client {
	clientOptions := newClientOptions()
	for _, option := range options {
		option.applyToClient(clientOptions)
	}
	return newClient(pluginrpcClient, clientOptions.caching)
}

// ClientOption is an option for a new Client.
type ClientOption interface {
	applyToClient(opts *clientOptions)
}

// ClientWithCaching returns a new ClientOption that will result caching for items
// expected to be static:
//
// - PluginInfo from GetPluginInfo.
//
// The default is to not cache.
func ClientWithCaching() ClientOption {
	return clientWithCachingOption{}
}

// GetPluginInfoCallOption is an option for a Client.GetPluginInfo call.
type GetPluginInfoCallOption func(*getPluginInfoCallOptions)

// *** PRIVATE ***

type client struct {
	pluginrpcClient pluginrpc.Client

	caching bool

	// Singleton ordering: pluginInfo -> pluginInfoServiceClient
	pluginInfo              *cache.Singleton[PluginInfo]
	pluginInfoServiceClient *cache.Singleton[v1pluginrpc.PluginInfoServiceClient]
}

func newClient(
	pluginrpcClient pluginrpc.Client,
	caching bool,
) *client {
	client := &client{
		pluginrpcClient: pluginrpcClient,
		caching:         caching,
	}
	client.pluginInfo = cache.NewSingleton(client.getPluginInfoUncached)
	client.pluginInfoServiceClient = cache.NewSingleton(client.getPluginInfoServiceClientUncached)
	return client
}

func (c *client) GetPluginInfo(ctx context.Context, _ ...GetPluginInfoCallOption) (PluginInfo, error) {
	if !c.caching {
		return c.getPluginInfoUncached(ctx)
	}
	return c.pluginInfo.Get(ctx)
}

func (c *client) getPluginInfoUncached(ctx context.Context) (PluginInfo, error) {
	pluginInfoServiceClient, err := c.pluginInfoServiceClient.Get(ctx)
	if err != nil {
		return nil, err
	}
	response, err := pluginInfoServiceClient.GetPluginInfo(
		ctx,
		&infov1.GetPluginInfoRequest{},
	)
	if err != nil {
		return nil, err
	}
	return pluginInfoForProtoPluginInfo(response.GetPluginInfo())
}

func (c *client) getPluginInfoServiceClientUncached(ctx context.Context) (v1pluginrpc.PluginInfoServiceClient, error) {
	spec, err := c.pluginrpcClient.Spec(ctx)
	if err != nil {
		return nil, err
	}
	for _, procedurePath := range []string{
		v1pluginrpc.PluginInfoServiceGetPluginInfoPath,
	} {
		if spec.ProcedureForPath(procedurePath) == nil {
			return nil, pluginrpc.NewErrorf(pluginrpc.CodeUnimplemented, "procedure unimplemented: %q", procedurePath)
		}
	}
	return v1pluginrpc.NewPluginInfoServiceClient(c.pluginrpcClient)
}

func (*client) isClient() {}

type clientOptions struct {
	caching bool
}

func newClientOptions() *clientOptions {
	return &clientOptions{}
}

type clientWithCachingOption struct{}

func (clientWithCachingOption) applyToClient(clientOptions *clientOptions) {
	clientOptions.caching = true
}

type getPluginInfoCallOptions struct{}
