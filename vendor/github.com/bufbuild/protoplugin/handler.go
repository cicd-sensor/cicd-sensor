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

package protoplugin

import (
	"context"
)

// Handler is the interface implemented by protoc plugin implementations.
type Handler interface {
	// Handle handles a CodeGeneratorRequest and turns it into a CodeGeneratorResponse.
	//
	// Implementations of Handler can assume that the CodeGeneratorRequest has been validated.
	//
	//   - The CodeGeneratorRequest will not be nil.
	//   - FileToGenerate and ProtoFile will be non-empty.
	//   - Each FileDescriptorProto in ProtoFile will have a valid path as the name field.
	//   - Each value of FileToGenerate will be a valid path.
	//   - Each value of FileToGenerate will have a corresponding value in ProtoFile.
	//
	// If SourceFileDescriptors is not empty:
	//
	//   - Each FileDescriptorProto in SourceFileDescriptors will have a valid path as the name field.
	//   - The values of FileToGenerate will have a 1-1 mapping to the names in SourceFileDescriptors.
	//
	// Paths are considered valid if they are non-empty, relative, use '/' as the path separator, do not jump context,
	// and have `.proto` as the file extension.
	//
	// If an error is returned, it will not be returned as an error on the CodeGeneratorRequest, instead it will be
	// treated as an error of the plugin itself, and the plugin will return a non-zero exit code. If there is an error
	// with the actual input .proto files that results in your plugin's business logic not being able to be executed
	// (for example, a missing option), this error should be added to the response via SetError.
	Handle(
		ctx context.Context,
		pluginEnv PluginEnv,
		responseWriter ResponseWriter,
		request Request,
	) error
}

// HandlerFunc is a function that implements Handler.
type HandlerFunc func(context.Context, PluginEnv, ResponseWriter, Request) error

// Handle implements Handler.
func (h HandlerFunc) Handle(
	ctx context.Context,
	pluginEnv PluginEnv,
	responseWriter ResponseWriter,
	request Request,
) error {
	return h(ctx, pluginEnv, responseWriter, request)
}
