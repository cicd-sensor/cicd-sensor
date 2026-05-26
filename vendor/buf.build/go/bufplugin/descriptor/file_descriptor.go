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
	"fmt"
	"slices"

	descriptorv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/descriptor/v1"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// FileDescriptor is a protoreflect.FileDescriptor with additional properties.
//
// The raw FileDescriptorProto is also provided from this interface.
// are provided.
type FileDescriptor interface {
	// ProtoreflectFileDescriptor returns the protoreflect.FileDescriptor representing this FileDescriptor.
	ProtoreflectFileDescriptor() protoreflect.FileDescriptor

	// FileDescriptorProto returns the FileDescriptorProto representing this File.
	//
	// This is not a copy - do not modify!
	FileDescriptorProto() *descriptorpb.FileDescriptorProto
	// IsImport returns true if the File is an import.
	//
	// An import is a file that is either:
	//
	//   - A Well-Known Type included from the compiler and imported by a targeted file.
	//   - A file that was included from a Buf module dependency and imported by a targeted file.
	//   - A file that was not targeted, but was imported by a targeted file.
	//
	// We use "import" as this matches with the protoc concept of --include_imports, however
	// import is a bit of an overloaded term.
	IsImport() bool

	// IsSyntaxUnspecified denotes whether the file did not have a syntax explicitly specified.
	//
	// Per the FileDescriptorProto spec, it would be fine in this case to just leave the syntax field
	// unset to denote this and to set the syntax field to "proto2" if it is specified. However,
	// protoc does not set the syntax field if it was "proto2". Plugins may want to differentiate
	// between "proto2" and unset, and this field allows them to.
	IsSyntaxUnspecified() bool

	// UnusedDependencyIndexes are the indexes within the Dependency field on FileDescriptorProto for
	// those dependencies that are not used.
	//
	// This matches the shape of the PublicDependency and WeakDependency fields.
	UnusedDependencyIndexes() []int32

	// ToProto converts the FileDescriptor to its Protobuf representation.
	ToProto() *descriptorv1.FileDescriptor

	isFileDescriptor()
}

// FileDescriptorsForProtoFileDescriptors returns a new slice of FileDescriptors for the given descriptorv1.FileDescriptorDescriptors.
func FileDescriptorsForProtoFileDescriptors(protoFileDescriptors []*descriptorv1.FileDescriptor) ([]FileDescriptor, error) {
	if len(protoFileDescriptors) == 0 {
		return nil, nil
	}
	fileNameToProtoFileDescriptor := make(map[string]*descriptorv1.FileDescriptor, len(protoFileDescriptors))
	fileDescriptorProtos := make([]*descriptorpb.FileDescriptorProto, len(protoFileDescriptors))
	for i, protoFileDescriptor := range protoFileDescriptors {
		fileDescriptorProto := protoFileDescriptor.GetFileDescriptorProto()
		fileName := fileDescriptorProto.GetName()
		if _, ok := fileNameToProtoFileDescriptor[fileName]; ok {
			//  This should have been validated via protovalidate.
			return nil, fmt.Errorf("duplicate file name: %q", fileName)
		}
		fileDescriptorProtos[i] = fileDescriptorProto
		fileNameToProtoFileDescriptor[fileName] = protoFileDescriptor
	}

	protoregistryFiles, err := protodesc.NewFiles(
		&descriptorpb.FileDescriptorSet{
			File: fileDescriptorProtos,
		},
	)
	if err != nil {
		return nil, err
	}

	fileDescriptors := make([]FileDescriptor, 0, len(protoFileDescriptors))
	protoregistryFiles.RangeFiles(
		func(protoreflectFileDescriptor protoreflect.FileDescriptor) bool {
			protoFileDescriptor, ok := fileNameToProtoFileDescriptor[protoreflectFileDescriptor.Path()]
			if !ok {
				// If the protoreflect API is sane, this should never happen.
				// However, the protoreflect API is not sane.
				err = fmt.Errorf("unknown file: %q", protoreflectFileDescriptor.Path())
				return false
			}
			fileDescriptors = append(
				fileDescriptors,
				newFileDescriptor(
					protoreflectFileDescriptor,
					protoFileDescriptor.GetFileDescriptorProto(),
					protoFileDescriptor.GetIsImport(),
					protoFileDescriptor.GetIsSyntaxUnspecified(),
					protoFileDescriptor.GetUnusedDependency(),
				),
			)
			return true
		},
	)
	if err != nil {
		return nil, err
	}
	if len(fileDescriptors) != len(protoFileDescriptors) {
		// If the protoreflect API is sane, this should never happen.
		// However, the protoreflect API is not sane.
		return nil, fmt.Errorf("expected %d files from protoregistry, got %d", len(protoFileDescriptors), len(fileDescriptors))
	}
	return fileDescriptors, nil
}

// *** PRIVATE ***

type fileDescriptor struct {
	protoreflectFileDescriptor protoreflect.FileDescriptor
	fileDescriptorProto        *descriptorpb.FileDescriptorProto
	isImport                   bool
	isSyntaxUnspecified        bool
	unusedDependencyIndexes    []int32
}

func newFileDescriptor(
	protoreflectFileDescriptor protoreflect.FileDescriptor,
	fileDescriptorProto *descriptorpb.FileDescriptorProto,
	isImport bool,
	isSyntaxUnspecified bool,
	unusedDependencyIndexes []int32,
) *fileDescriptor {
	return &fileDescriptor{
		protoreflectFileDescriptor: protoreflectFileDescriptor,
		fileDescriptorProto:        fileDescriptorProto,
		isImport:                   isImport,
		isSyntaxUnspecified:        isSyntaxUnspecified,
		unusedDependencyIndexes:    unusedDependencyIndexes,
	}
}

func (f *fileDescriptor) ProtoreflectFileDescriptor() protoreflect.FileDescriptor {
	return f.protoreflectFileDescriptor
}

func (f *fileDescriptor) FileDescriptorProto() *descriptorpb.FileDescriptorProto {
	return f.fileDescriptorProto
}

func (f *fileDescriptor) IsImport() bool {
	return f.isImport
}

func (f *fileDescriptor) IsSyntaxUnspecified() bool {
	return f.isSyntaxUnspecified
}

func (f *fileDescriptor) UnusedDependencyIndexes() []int32 {
	return slices.Clone(f.unusedDependencyIndexes)
}

func (f *fileDescriptor) ToProto() *descriptorv1.FileDescriptor {
	if f == nil {
		return nil
	}
	return &descriptorv1.FileDescriptor{
		FileDescriptorProto: f.fileDescriptorProto,
		IsImport:            f.isImport,
		IsSyntaxUnspecified: f.isSyntaxUnspecified,
		UnusedDependency:    f.unusedDependencyIndexes,
	}
}

func (*fileDescriptor) isFileDescriptor() {}
