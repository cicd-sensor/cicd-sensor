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
	"slices"
	"sync"

	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

// Request wraps a CodeGeneratorRequest.
//
// Request contains a private method to ensure that it is not constructed outside this package, to
// enable us to modify the Request interface in the future without breaking compatibility.
type Request interface {
	// Parameter returns the value of the parameter field on the CodeGeneratorRequest.
	Parameter() string
	// FileDescriptorsToGenerate returns the FileDescriptors for the files specified by the
	// file_to_generate field on the CodeGeneratorRequest.
	//
	// The caller can assume that all FileDescriptors have a valid path as the name field.
	// Paths are considered valid if they are non-empty, relative, use '/' as the path separator, do not jump context,
	// and have `.proto` as the file extension.
	FileDescriptorsToGenerate() ([]protoreflect.FileDescriptor, error)
	// AllFiles returns the a Files registry for all files in the CodeGeneratorRequest.
	//
	// This matches with the proto_file field on the CodeGeneratorRequest, with the FileDescriptorProtos
	// from the source_file_descriptors field used for the files in file_to_geneate if WithSourceRetentionOptions
	// is specified.
	//
	// The caller can assume that all FileDescriptors have a valid path as the name field.
	// Paths are considered valid if they are non-empty, relative, use '/' as the path separator, do not jump context,
	// and have `.proto` as the file extension.
	AllFiles() (*protoregistry.Files, error)
	// FileDescriptorProtosToGenerate returns the FileDescriptors for the files specified by the
	// file_to_generate field.
	//
	// The caller can assume that all FileDescriptorProtoss have a valid path as the name field.
	// Paths are considered valid if they are non-empty, relative, use '/' as the path separator, do not jump context,
	// and have `.proto` as the file extension.
	FileDescriptorProtosToGenerate() []*descriptorpb.FileDescriptorProto
	// AllFileDescriptorProtos returns the FileDescriptorProtos for all files in the CodeGeneratorRequest.
	//
	// This matches with the proto_file field on the CodeGeneratorRequest, with the FileDescriptorProtos
	// from the source_file_descriptors field used for the files in file_to_geneate if WithSourceRetentionOptions
	// is specified.
	//
	// The caller can assume that all FileDescriptorProtoss have a valid path as the name field.
	// Paths are considered valid if they are non-empty, relative, use '/' as the path separator, do not jump context,
	// and have `.proto` as the file extension.
	AllFileDescriptorProtos() []*descriptorpb.FileDescriptorProto
	// CompilerVersion returns the specified compiler_version on the CodeGeneratorRequest.
	//
	// If the compiler_version field was not present, nil is returned.
	//
	// The caller can assume that the major, minor, and patch values are non-negative.
	CompilerVersion() *CompilerVersion
	// CodeGeneratorRequest returns the raw underlying CodeGeneratorRequest.
	//
	// The returned CodeGeneratorRequest is a not copy - do not modify it! If you would
	// like to modify the CodeGeneratorRequest, use proto.Clone to create a copy.
	CodeGeneratorRequest() *pluginpb.CodeGeneratorRequest
	// WithSourceRetentionOptions will return a copy of the Request that will result in all
	// methods returning descriptors with source-retention options retained on files to generate.
	//
	// By default, only runtime-retention options are included on files to generate. Note that
	// source-retention options are always included on files not in file_to_generate.
	//
	// An error will be returned if the underlying CodeGeneratorRequest did not have source_file_descriptors populated.
	WithSourceRetentionOptions() (Request, error)

	isRequest()
}

// NewRequest returns a new Request for the CodeGeneratorRequest.
//
// The CodeGeneratorRequest will be validated as part of construction.
func NewRequest(codeGeneratorRequest *pluginpb.CodeGeneratorRequest) (Request, error) {
	if err := validateCodeGeneratorRequest(codeGeneratorRequest); err != nil {
		return nil, err
	}
	request := &request{
		codeGeneratorRequest: codeGeneratorRequest,
	}
	request.getFilesToGenerateMap =
		sync.OnceValue(request.getFilesToGenerateMapUncached)
	request.getSourceFileDescriptorNameToFileDescriptorProtoMap =
		sync.OnceValue(request.getSourceFileDescriptorNameToFileDescriptorProtoMapUncached)
	return request, nil
}

// *** PRIVATE ***

type request struct {
	codeGeneratorRequest *pluginpb.CodeGeneratorRequest

	getFilesToGenerateMap                               func() map[string]struct{}
	getSourceFileDescriptorNameToFileDescriptorProtoMap func() map[string]*descriptorpb.FileDescriptorProto

	sourceRetentionOptions bool
}

func (r *request) Parameter() string {
	return r.codeGeneratorRequest.GetParameter()
}

func (r *request) FileDescriptorsToGenerate() ([]protoreflect.FileDescriptor, error) {
	files, err := r.AllFiles()
	if err != nil {
		return nil, err
	}
	fileDescriptors := make([]protoreflect.FileDescriptor, len(r.codeGeneratorRequest.GetFileToGenerate()))
	for i, fileToGenerate := range r.codeGeneratorRequest.GetFileToGenerate() {
		fileDescriptor, err := files.FindFileByPath(fileToGenerate)
		if err != nil {
			return nil, err
		}
		fileDescriptors[i] = fileDescriptor
	}
	return fileDescriptors, nil
}

func (r *request) AllFiles() (*protoregistry.Files, error) {
	return protodesc.NewFiles(&descriptorpb.FileDescriptorSet{File: r.AllFileDescriptorProtos()})
}

func (r *request) FileDescriptorProtosToGenerate() []*descriptorpb.FileDescriptorProto {
	// If we want source-retention options, source_file_descriptors is all we need.
	//
	// We have validated that source_file_descriptors is populated via WithSourceRetentionOptions.
	if r.sourceRetentionOptions {
		return slices.Clone(r.codeGeneratorRequest.GetSourceFileDescriptors())
	}
	// Otherwise, we need to get the values in proto_file that are in file_to_generate.
	filesToGenerateMap := r.getFilesToGenerateMap()
	fileDescriptorProtos := make([]*descriptorpb.FileDescriptorProto, 0, len(r.codeGeneratorRequest.GetFileToGenerate()))
	for _, protoFile := range r.codeGeneratorRequest.GetProtoFile() {
		if _, ok := filesToGenerateMap[protoFile.GetName()]; ok {
			fileDescriptorProtos = append(fileDescriptorProtos, protoFile)
		}
	}
	return fileDescriptorProtos
}

func (r *request) AllFileDescriptorProtos() []*descriptorpb.FileDescriptorProto {
	// If we do not want source-retention options, proto_file is all we need.
	if !r.sourceRetentionOptions {
		return slices.Clone(r.codeGeneratorRequest.GetProtoFile())
	}
	// Otherwise, we need to replace the values in proto_file that are in file_to_generate
	// with the values from source_file_descriptors.
	//
	// We have validated that source_file_descriptors is populated via WithSourceRetentionOptions.
	filesToGenerateMap := r.getFilesToGenerateMap()
	sourceFileDescriptorNameToFileDescriptorProtoMap := r.getSourceFileDescriptorNameToFileDescriptorProtoMap()
	fileDescriptorProtos := make([]*descriptorpb.FileDescriptorProto, len(r.codeGeneratorRequest.GetProtoFile()))
	for i, protoFile := range r.codeGeneratorRequest.GetProtoFile() {
		if _, ok := filesToGenerateMap[protoFile.GetName()]; ok {
			// We assume we've done validation that source_file_descriptors contains file_to_generate.
			protoFile = sourceFileDescriptorNameToFileDescriptorProtoMap[protoFile.GetName()]
		}
		fileDescriptorProtos[i] = protoFile
	}
	return fileDescriptorProtos
}

func (r *request) CompilerVersion() *CompilerVersion {
	// We have already validated the *pluginpb.Version via validateCompilerVersion, no need to validate here.
	if version := r.codeGeneratorRequest.GetCompilerVersion(); version != nil {
		return &CompilerVersion{
			Major:  int(version.GetMajor()),
			Minor:  int(version.GetMinor()),
			Patch:  int(version.GetPatch()),
			Suffix: version.GetSuffix(),
		}
	}
	return nil
}

func (r *request) CodeGeneratorRequest() *pluginpb.CodeGeneratorRequest {
	return r.codeGeneratorRequest
}

func (r *request) WithSourceRetentionOptions() (Request, error) {
	if err := r.validateSourceFileDescriptorsPresent(); err != nil {
		return nil, err
	}
	return &request{
		codeGeneratorRequest:                                r.codeGeneratorRequest,
		getFilesToGenerateMap:                               r.getFilesToGenerateMap,
		getSourceFileDescriptorNameToFileDescriptorProtoMap: r.getSourceFileDescriptorNameToFileDescriptorProtoMap,
		sourceRetentionOptions:                              true,
	}, nil
}

func (r *request) validateSourceFileDescriptorsPresent() error {
	if len(r.codeGeneratorRequest.GetSourceFileDescriptors()) == 0 &&
		len(r.codeGeneratorRequest.GetProtoFile()) > 0 {
		return errors.New("source_file_descriptors not set on CodeGeneratorRequest but source-retention options requested - you likely need to upgrade your protobuf compiler")
	}
	return nil
}

func (r *request) getFilesToGenerateMapUncached() map[string]struct{} {
	filesToGenerateMap := make(
		map[string]struct{},
		len(r.codeGeneratorRequest.GetFileToGenerate()),
	)
	for _, fileToGenerate := range r.codeGeneratorRequest.GetFileToGenerate() {
		filesToGenerateMap[fileToGenerate] = struct{}{}
	}
	return filesToGenerateMap
}

func (r *request) getSourceFileDescriptorNameToFileDescriptorProtoMapUncached() map[string]*descriptorpb.FileDescriptorProto {
	sourceFileDescriptorNameToFileDescriptorProtoMap := make(
		map[string]*descriptorpb.FileDescriptorProto,
		len(r.codeGeneratorRequest.GetSourceFileDescriptors()),
	)
	for _, sourceFileDescriptor := range r.codeGeneratorRequest.GetSourceFileDescriptors() {
		sourceFileDescriptorNameToFileDescriptorProtoMap[sourceFileDescriptor.GetName()] = sourceFileDescriptor
	}
	return sourceFileDescriptorNameToFileDescriptorProtoMap
}

func (*request) isRequest() {}
