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
	"errors"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

// ResponseWriter is used by implementations of Handler to construct CodeGeneratorResponses.
//
// ResponseWriter contains a private method to ensure that it is not constructed outside this package, to
// enable us to modify the ResponseWriter interface in the future without breaking compatibility.
type ResponseWriter interface {
	// AddFile adds the file with the given content to the response.
	//
	// This takes care of the most common case of adding a CodeGeneratorResponse.File with content. If you need add a
	// CodeGeneratorResponse.File with insertion points or any other feature, use AddCodeGeneratorResponseFiles.
	//
	// The plugin will exit with a non-zero exit code if the name is an invalid path.
	// Paths are considered valid if they are non-empty, relative, use '/' as the path separator, and do not jump context.
	//
	// If a file with the same name was already added, or the file name is not cleaned, a warning will be produced.
	AddFile(name string, content string)
	// AddError adds the error message on the response.
	//
	// If there is an error with the actual input .proto files that results in your plugin's business logic not being able to be executed
	// (for example, a missing option), this error should be added to the response via SetError. If there is a system error, the
	// Handler should return error, which will result in the plugin exiting with a non-zero exit code.
	//
	// If there is an existing error message already added, the new error will be appended.
	// Note that empty error messages will be ignored (ie it will be as if no error was set).
	AddError(message string)
	// SetFeatureProto3Optional sets the FEATURE_PROTO3_OPTIONAL feature on the response.
	//
	// This function should be preferred over SetSupportedFeatures. Use SetSupportedFeatures only if you need low-level access.
	SetFeatureProto3Optional()
	// SetFeatureSupportsEditions sets the FEATURE_SUPPORTS_EDITIONS feature on the response along
	// with the given min and max editions.
	//
	// This function should be preferred over calling SetSupportedFeatures, SetMinimumEdition, and SetMaximumEdition separately.
	// Use SetSupportedFeatures, SetMinimumEdition, and SetMaximumEdition only if you need low-level access.
	//
	// If this was previously called, the result will be overwritten. That is, if a new minimumEdition and maximumEdition
	// are specified, the last call wins.
	//
	// The plugin will exit with a non-zero exit code if the minimum edition is greater than the maximum edition.
	SetFeatureSupportsEditions(minimumEdition descriptorpb.Edition, maximumEdition descriptorpb.Edition)
	// AddCodeGeneratorResponseFiles adds the CodeGeneratorResponse.Files to the response.
	//
	// See the documentation on CodeGeneratorResponse.File for the exact semantics.
	//
	// If you are just adding file content, use the simpler AddFile. This function is for lower-level access.
	//
	// The plugin will exit with a non-zero exit code if any of the following are true:
	//
	// - The CodeGeneratorResponse_File is nil.
	// - The name is an invalid path.
	//
	// Paths are considered valid if they are non-empty, relative, use '/' as the path separator, and do not jump context.
	//
	// If a file with the same name was already added, or the file name is not cleaned, a warning will be produced.
	AddCodeGeneratorResponseFiles(files ...*pluginpb.CodeGeneratorResponse_File)
	// SetSupportedFeatures the given features on the response.
	//
	// You likely want to use the specific feature functions instead of this function.
	// This function is for lower-level access.
	//
	// If there are existing features already added, they will be overwritten.
	//
	// If the features are not represented in the known CodeGeneratorResponse.Features,
	// the plugin will exit with a non-zero exit code.
	SetSupportedFeatures(supportedFeatures uint64)
	// SetMinimumEdition sets the minimum edition.
	//
	// If you want to specify that you are supporting editions, it is likely easier to use
	// SetFeatureSupportsEditions. This function is for those callers needing to have lower-level access.
	//
	// If this was previously called, the result will be overwritten.
	//
	// The plugin will exit with a non-zero exit code if the minimum edition is greater than the maximum edition.
	SetMinimumEdition(minimumEdition int32)
	// SetMaximumEdition sets the maximum edition.
	//
	// If you want to specify that you are supporting editions, it is likely easier to use
	// SetFeatureSupportsEditions. This function is for those callers needing to have lower-level access.
	//
	// If this was previously called, the result will be overwritten.
	//
	// The plugin will exit with a non-zero exit code if the minimum edition is greater than the maximum edition.
	SetMaximumEdition(maximumEdition int32)
	// ToCodeGeneratorResponse creates a CodeGeneratorResponse from the values written to the ResponseWriter.
	//
	// Most users of this library will not need to call this function. This function is only used if you are
	// invoking Handlers outside of Main or Run.
	//
	// This function can be called exactly once. Future calls to this function will result in an error.
	ToCodeGeneratorResponse() (*pluginpb.CodeGeneratorResponse, error)

	isResponseWriter()
}

// NewResponseWriter returns a new ResponseWriter.
func NewResponseWriter(options ...ResponseWriterOption) ResponseWriter {
	responseWriter := &responseWriter{
		codeGeneratorResponse: &pluginpb.CodeGeneratorResponse{},
	}
	for _, option := range options {
		option(responseWriter)
	}
	return responseWriter
}

// ResponseWriterOption is an option for a new ResponseWriter.
type ResponseWriterOption func(*responseWriter)

// ResponseWriterWithLenientValidation returns a new ResponseWriterOption that says handle non-critical CodeGeneratorResponse
// validation issues as warnings that will be handled by the given warning handler.
//
// This allows the following issues to result in warnings instead of errors:
//
//   - Duplicate file names for files without insertion points. If the same file name is used two or more times for
//     files without insertion points, the first occurrence of the file will be used and subsequent occurrences will
//     be dropped.
//   - File names that are not equal to filepath.ToSlash(filepath.Clean(name)). The file name will be modified
//     with this normalization.
//
// These issues result in CodeGeneratorResponses that are not properly formed per the CodeGeneratorResponse
// spec, however both protoc and buf have been resilient to these issues for years. There are numerous plugins
// out in the wild that have these issues, and protoplugin should be able to function as a proxy to these
// plugins without error.
//
// Most users of protoplugin should not use this option, this should only be used for plugins that proxy to other
// plugins. If you are authoring a standalone plugin, you should instead make sure your responses are completely correct.
//
// The default is to error on these issues.
//
// Implementers of lenientValidateErrorFunc can assume that errors passed will be non-nil and have non-empty
// values for err.Error().
func ResponseWriterWithLenientValidation(lenientValidateErrorFunc func(error)) ResponseWriterOption {
	return func(responseWriter *responseWriter) {
		responseWriter.lenientValidateErrorFunc = lenientValidateErrorFunc
	}
}

// *** PRIVATE ***

type responseWriter struct {
	codeGeneratorResponse *pluginpb.CodeGeneratorResponse
	written               bool

	lenientValidateErrorFunc func(error)

	lock sync.RWMutex
}

func (r *responseWriter) AddFile(name string, content string) {
	r.AddCodeGeneratorResponseFiles(
		&pluginpb.CodeGeneratorResponse_File{
			Name:    proto.String(name),
			Content: proto.String(content),
		},
	)
}

func (r *responseWriter) AddError(message string) {
	r.lock.Lock()
	defer r.lock.Unlock()

	// plugin.proto specifies that only non-empty errors are considered errors.
	// This is also consistent with protoc's behavior.
	// Ref: https://github.com/protocolbuffers/protobuf/blob/069f989b483e63005f87ab309de130677718bbec/src/google/protobuf/compiler/plugin.proto#L100-L108.
	if message == "" {
		return
	}
	if existingError := r.codeGeneratorResponse.GetError(); existingError != "" {
		message = existingError + "; " + message
	}
	r.codeGeneratorResponse.Error = proto.String(message)
}

func (r *responseWriter) SetFeatureProto3Optional() {
	r.addSupportedFeatures(uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL))
}

func (r *responseWriter) SetFeatureSupportsEditions(minimumEdition descriptorpb.Edition, maximumEdition descriptorpb.Edition) {
	r.addSupportedFeatures(uint64(pluginpb.CodeGeneratorResponse_FEATURE_SUPPORTS_EDITIONS))
	r.SetMinimumEdition(int32(minimumEdition))
	r.SetMaximumEdition(int32(maximumEdition))
}

func (r *responseWriter) AddCodeGeneratorResponseFiles(files ...*pluginpb.CodeGeneratorResponse_File) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.codeGeneratorResponse.File = append(r.codeGeneratorResponse.GetFile(), files...)
}

func (r *responseWriter) SetSupportedFeatures(supportedFeatures uint64) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if supportedFeatures == 0 {
		r.codeGeneratorResponse.SupportedFeatures = nil
	} else {
		r.codeGeneratorResponse.SupportedFeatures = proto.Uint64(supportedFeatures)
	}
}

func (r *responseWriter) SetMinimumEdition(minimumEdition int32) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if minimumEdition == 0 {
		r.codeGeneratorResponse.MinimumEdition = nil
	} else {
		r.codeGeneratorResponse.MinimumEdition = proto.Int32(minimumEdition)
	}
}

func (r *responseWriter) SetMaximumEdition(maximumEdition int32) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if maximumEdition == 0 {
		r.codeGeneratorResponse.MaximumEdition = nil
	} else {
		r.codeGeneratorResponse.MaximumEdition = proto.Int32(maximumEdition)
	}
}

func (r *responseWriter) ToCodeGeneratorResponse() (*pluginpb.CodeGeneratorResponse, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if r.written {
		// We do modifications of the CodeGeneratorResponse in validateAndNormalizeCodeGeneratorResponse, so if someone were
		// to somehow reuse a ResponseWriter, they may get unexpected results in the future.
		//
		// This is an edge case - ResponseWriters are given to Handlers, so to reuse one would be very weird.
		return nil, errors.New("ResponseWriter cannot be reused")
	}
	r.written = true

	if err := validateAndNormalizeCodeGeneratorResponse(r.codeGeneratorResponse, r.lenientValidateErrorFunc); err != nil {
		return nil, err
	}
	return r.codeGeneratorResponse, nil
}

func (r *responseWriter) addSupportedFeatures(supportedFeatures uint64) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.codeGeneratorResponse.SupportedFeatures = proto.Uint64(r.codeGeneratorResponse.GetSupportedFeatures() | supportedFeatures)
}

func (*responseWriter) isResponseWriter() {}
