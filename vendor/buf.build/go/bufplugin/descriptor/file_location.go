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

package descriptor

import (
	"slices"

	descriptorv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/descriptor/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// FileLocation is a reference to a FileDescriptor or to a location within a FileDescriptor.
//
// A FileLocation always has a file name.
type FileLocation interface {
	// FileDescriptor is the FileDescriptor associated with the FileLocation.
	//
	// Always present.
	FileDescriptor() FileDescriptor
	// SourcePath returns the path within the FileDescriptorProto of the FileLocation.
	SourcePath() protoreflect.SourcePath

	// StartLine returns the zero-indexed start line, if known.
	StartLine() int
	// StartColumn returns the zero-indexed start column, if known.
	StartColumn() int
	// EndLine returns the zero-indexed end line, if known.
	EndLine() int
	// EndColumn returns the zero-indexed end column, if known.
	EndColumn() int
	// LeadingComments returns any leading comments, if known.
	LeadingComments() string
	// TrailingComments returns any trailing comments, if known.
	TrailingComments() string
	// LeadingDetachedComments returns any leading detached comments, if known.
	LeadingDetachedComments() []string
	// ToProto converts the FileLocation to its Protobuf representation.
	ToProto() *descriptorv1.FileLocation

	unclonedSourcePath() protoreflect.SourcePath
	unclonedLeadingDetachedComments() []string

	isFileLocation()
}

// NewFileLocation returns a new FileLocation.
func NewFileLocation(
	fileDescriptor FileDescriptor,
	sourceLocation protoreflect.SourceLocation,
) FileLocation {
	return &fileLocation{
		fileDescriptor: fileDescriptor,
		sourceLocation: sourceLocation,
	}
}

// *** PRIVATE ***

type fileLocation struct {
	fileDescriptor FileDescriptor
	sourceLocation protoreflect.SourceLocation
}

func (l *fileLocation) FileDescriptor() FileDescriptor {
	return l.fileDescriptor
}

func (l *fileLocation) SourcePath() protoreflect.SourcePath {
	return slices.Clone(l.sourceLocation.Path)
}

func (l *fileLocation) StartLine() int {
	return l.sourceLocation.StartLine
}

func (l *fileLocation) StartColumn() int {
	return l.sourceLocation.StartColumn
}

func (l *fileLocation) EndLine() int {
	return l.sourceLocation.EndLine
}

func (l *fileLocation) EndColumn() int {
	return l.sourceLocation.EndColumn
}

func (l *fileLocation) LeadingComments() string {
	return l.sourceLocation.LeadingComments
}

func (l *fileLocation) TrailingComments() string {
	return l.sourceLocation.TrailingComments
}

func (l *fileLocation) LeadingDetachedComments() []string {
	return slices.Clone(l.sourceLocation.LeadingDetachedComments)
}

func (l *fileLocation) ToProto() *descriptorv1.FileLocation {
	if l == nil {
		return nil
	}
	return &descriptorv1.FileLocation{
		FileName:   l.fileDescriptor.ProtoreflectFileDescriptor().Path(),
		SourcePath: l.sourceLocation.Path,
	}
}

func (l *fileLocation) unclonedSourcePath() protoreflect.SourcePath {
	return l.sourceLocation.Path
}

func (l *fileLocation) unclonedLeadingDetachedComments() []string {
	return l.sourceLocation.LeadingDetachedComments
}

func (*fileLocation) isFileLocation() {}
