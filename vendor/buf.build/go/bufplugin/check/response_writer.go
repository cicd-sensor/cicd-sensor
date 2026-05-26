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
	"sync"

	"buf.build/go/bufplugin/descriptor"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var errCannotReuseResponseWriter = errors.New("cannot reuse ResponseWriter")

// ResponseWriter is used by plugin implmentations to add Annotations to responses.
//
// A ResponseWriter is tied to a specific rule, and is passed to a RuleHandler.
// The ID of the Rule will be automatically populated for any added Annotations.
type ResponseWriter interface {
	// AddAnnotation adds an Annotation with the rule ID that is tied to this ResponseWriter.
	//
	// Fields of the Annotation are controlled with AddAnnotationOptions, of which there are several:
	//
	//   - WithMessage/WithMessagef: Add a message to the Annotation.
	//   - WithDescriptor/WithAgainstDescriptor: Use the protoreflect.Descriptor to determine Location information.
	//   - WithFileName/WithAgainstFileName: Use the given file name on the Location.
	//   - WithFileNameAndSourcePath/WithAgainstFileNameAndSourcePath: Use the given explicit file name and source path on the Location.
	//
	// There are some rules to note when using AddAnnotationOptions:
	//
	//   - Multiple calls of WithMessage/WithMessagef will overwrite previous calls.
	//   - You must either use WithDescriptor, or use WithFileName/WithSourcePath, but you cannot
	//     use these together. Location information is determined either from the Descriptor, or
	//     from explicit setting via WithFileName/WithFileNameAndSourcePath. Same applies to the Against equivalents.
	//
	// Don't worry, these rules are verified when building a Response.
	//
	// Most users will use WithDescriptor/WithAgainstDescriptor as opposed to their lower-level variants.
	AddAnnotation(options ...AddAnnotationOption)

	isResponseWriter()
}

// AddAnnotationOption is an option with adding an Annotation to a ResponseWriter.
type AddAnnotationOption func(*addAnnotationOptions)

// WithMessage sets the message on the Annotation.
//
// If there are multiple calls to WithMessage or WithMessagef, the last one wins.
func WithMessage(message string) AddAnnotationOption {
	return func(addAnnotationOptions *addAnnotationOptions) {
		addAnnotationOptions.message = message
	}
}

// WithMessagef sets the message on the Annotation.
//
// If there are multiple calls to WithMessage or WithMessagef, the last one wins.
func WithMessagef(format string, args ...any) AddAnnotationOption {
	return func(addAnnotationOptions *addAnnotationOptions) {
		addAnnotationOptions.message = fmt.Sprintf(format, args...)
	}
}

// WithDescriptor will set the Location on the Annotation by extracting file and source path
// information from the descriptor itself.
//
// It is not valid to use WithDescriptor if also using either WithFileName or WithSourcePath.
func WithDescriptor(descriptor protoreflect.Descriptor) AddAnnotationOption {
	return func(addAnnotationOptions *addAnnotationOptions) {
		addAnnotationOptions.descriptor = descriptor
	}
}

// WithFileName will set the FileName on the Annotation's Location directly.
//
// Typically, most users will use WithDescriptor to accomplish this task.
//
// This will not set any line/column information. To do so, use WithFileNameAndSourcePath.
//
// It is not valid to use WithDescriptor if also using either WithFileName
// or WithFileNameAndSourcePath.
func WithFileName(fileName string) AddAnnotationOption {
	return func(addAnnotationOptions *addAnnotationOptions) {
		addAnnotationOptions.fileName = fileName
	}
}

// WithFileNameAndSourcePath will set the SourcePath on the Annotation's Location directly.
//
// Typically, most users will use WithDescriptor to accomplish this task.
//
// It is not valid to use WithDescriptor if also using either WithFileName
// or WithFileNameAndSourcePath.
func WithFileNameAndSourcePath(fileName string, sourcePath protoreflect.SourcePath) AddAnnotationOption {
	return func(addAnnotationOptions *addAnnotationOptions) {
		addAnnotationOptions.fileName = fileName
		addAnnotationOptions.sourcePath = sourcePath
	}
}

// WithAgainstDescriptor will set the AgainstLocation on the Annotation by extracting file and
// source path information from the descriptor itself.
//
// It is not valid to use WithAgainstDescriptor if also using either WithAgainstFileName or
// WithAgainstSourcePath.
func WithAgainstDescriptor(againstDescriptor protoreflect.Descriptor) AddAnnotationOption {
	return func(addAnnotationOptions *addAnnotationOptions) {
		addAnnotationOptions.againstDescriptor = againstDescriptor
	}
}

// WithAgainstFileName will set the FileName on the Annotation's AgainstLocation directly.
//
// Typically, most users will use WithAgainstDescriptor to accomplish this task.
//
// This will not set any line/column information. To do so, use WithAgainstFileNameAndSourcePath.
//
// It is not valid to use WithAgainstDescriptor if also using either WithAgainstFileName or
// WithAgainstFileNameAndSourcePath.
func WithAgainstFileName(againstFileName string) AddAnnotationOption {
	return func(addAnnotationOptions *addAnnotationOptions) {
		addAnnotationOptions.againstFileName = againstFileName
	}
}

// WithAgainstFileNameAndSourcePath will set the Filename and SourcePath on the
// Annotation's AgainstLocation directly.
//
// Typically, most users will use WithAgainstDescriptor to accomplish this task.
//
// It is not valid to use WithAgainstDescriptor if also using either WithAgainstFileName or
// WithAgainstFileNameAndSourcePath.
func WithAgainstFileNameAndSourcePath(againstFileName string, againstSourcePath protoreflect.SourcePath) AddAnnotationOption {
	return func(addAnnotationOptions *addAnnotationOptions) {
		addAnnotationOptions.againstFileName = againstFileName
		addAnnotationOptions.againstSourcePath = againstSourcePath
	}
}

// *** PRIVATE ***

// multiResponseWriter is a ResponseWriter that can be used for multiple IDs. It differs
// from a ResponseWriter in that an ID must be provided to addAnnotation. A multiResponseWriter
// itself creates ResponseWriters.
//
// multiResponseWriter is used by checkClients and checkServiceHandlers.
type multiResponseWriter struct {
	fileNameToFileDescriptor        map[string]descriptor.FileDescriptor
	againstFileNameToFileDescriptor map[string]descriptor.FileDescriptor

	annotations []Annotation
	written     bool
	errs        []error
	lock        sync.RWMutex
}

func newMultiResponseWriter(request Request) (*multiResponseWriter, error) {
	fileNameToFileDescriptor, err := fileNameToFileDescriptorForFileDescriptors(request.FileDescriptors())
	if err != nil {
		return nil, err
	}
	againstFileNameToFileDescriptor, err := fileNameToFileDescriptorForFileDescriptors(request.AgainstFileDescriptors())
	if err != nil {
		return nil, err
	}
	return &multiResponseWriter{
		fileNameToFileDescriptor:        fileNameToFileDescriptor,
		againstFileNameToFileDescriptor: againstFileNameToFileDescriptor,
	}, nil
}

func (m *multiResponseWriter) newResponseWriter(id string) *responseWriter {
	return newResponseWriter(m, id)
}

func (m *multiResponseWriter) addAnnotation(
	ruleID string,
	options ...AddAnnotationOption,
) {
	addAnnotationOptions := newAddAnnotationOptions()
	for _, option := range options {
		option(addAnnotationOptions)
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	if err := validateAddAnnotationOptions(addAnnotationOptions); err != nil {
		m.errs = append(m.errs, err)
		return
	}

	if m.written {
		m.errs = append(m.errs, errCannotReuseResponseWriter)
		return
	}

	fileLocation, err := getFileLocationForAddAnnotationOptions(
		m.fileNameToFileDescriptor,
		addAnnotationOptions.descriptor,
		addAnnotationOptions.fileName,
		addAnnotationOptions.sourcePath,
	)
	if err != nil {
		m.errs = append(m.errs, err)
		return
	}
	againstFileLocation, err := getFileLocationForAddAnnotationOptions(
		m.againstFileNameToFileDescriptor,
		addAnnotationOptions.againstDescriptor,
		addAnnotationOptions.againstFileName,
		addAnnotationOptions.againstSourcePath,
	)
	if err != nil {
		m.errs = append(m.errs, err)
		return
	}
	annotation, err := newAnnotation(
		ruleID,
		addAnnotationOptions.message,
		fileLocation,
		againstFileLocation,
	)
	if err != nil {
		m.errs = append(m.errs, err)
		return
	}

	m.annotations = append(m.annotations, annotation)
}

func (m *multiResponseWriter) toResponse() (Response, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	if len(m.errs) > 0 {
		return nil, errors.Join(m.errs...)
	}
	if m.written {
		return nil, errCannotReuseResponseWriter
	}
	m.written = true

	return newResponse(m.annotations)
}

type responseWriter struct {
	multiResponseWriter *multiResponseWriter
	id                  string
}

func newResponseWriter(
	multiResponseWriter *multiResponseWriter,
	id string,
) *responseWriter {
	return &responseWriter{
		multiResponseWriter: multiResponseWriter,
		id:                  id,
	}
}

func (r *responseWriter) AddAnnotation(
	options ...AddAnnotationOption,
) {
	r.multiResponseWriter.addAnnotation(r.id, options...)
}

func (*responseWriter) isResponseWriter() {}

type addAnnotationOptions struct {
	message           string
	descriptor        protoreflect.Descriptor
	againstDescriptor protoreflect.Descriptor
	fileName          string
	sourcePath        protoreflect.SourcePath
	againstFileName   string
	againstSourcePath protoreflect.SourcePath
}

func newAddAnnotationOptions() *addAnnotationOptions {
	return &addAnnotationOptions{}
}

func validateAddAnnotationOptions(addAnnotationOptions *addAnnotationOptions) error {
	if addAnnotationOptions.descriptor != nil &&
		(addAnnotationOptions.fileName != "" || len(addAnnotationOptions.sourcePath) > 0) {
		return errors.New("cannot call both WithDescriptor and WithFileName or WithFileNameAndSourcePath")
	}
	if addAnnotationOptions.againstDescriptor != nil &&
		(addAnnotationOptions.againstFileName != "" || len(addAnnotationOptions.againstSourcePath) > 0) {
		return errors.New("cannot call both WithAgainstDescriptor and WithAgainstFileName or WithAgainstFileNameAndSourcePath")
	}
	if addAnnotationOptions.fileName == "" && len(addAnnotationOptions.sourcePath) > 0 {
		return errors.New("must set a non-empty FileName when calling WithFileNameAndSourcePath")
	}
	if addAnnotationOptions.againstFileName == "" && len(addAnnotationOptions.againstSourcePath) > 0 {
		return errors.New("must set a non-empty FileName when calling WithAgainstFileNameAndSourcePath")
	}
	return nil
}

func getFileLocationForAddAnnotationOptions(
	fileNameToFileDescriptor map[string]descriptor.FileDescriptor,
	protoreflectDescriptor protoreflect.Descriptor,
	fileName string,
	path protoreflect.SourcePath,
) (descriptor.FileLocation, error) {
	if protoreflectDescriptor != nil {
		// Technically, ParentFile() can be nil.
		if protoreflectFileDescriptor := protoreflectDescriptor.ParentFile(); protoreflectFileDescriptor != nil {
			fileDescriptor, ok := fileNameToFileDescriptor[protoreflectFileDescriptor.Path()]
			if !ok {
				return nil, fmt.Errorf("cannot add annotation for unknown file: %q", protoreflectFileDescriptor.Path())
			}
			return descriptor.NewFileLocation(
				fileDescriptor,
				protoreflectFileDescriptor.SourceLocations().ByDescriptor(protoreflectDescriptor),
			), nil
		}
		return nil, nil
	}
	if fileName != "" {
		var sourceLocation protoreflect.SourceLocation
		fileDescriptor, ok := fileNameToFileDescriptor[fileName]
		if !ok {
			return nil, fmt.Errorf("cannot add annotation for unknown file: %q", fileName)
		}
		if len(path) > 0 {
			sourceLocation = fileDescriptor.ProtoreflectFileDescriptor().SourceLocations().ByPath(path)
		}
		return descriptor.NewFileLocation(fileDescriptor, sourceLocation), nil
	}
	return nil, nil
}
