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
	"sort"

	checkv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/check/v1"
	descriptorv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/descriptor/v1"
	"buf.build/go/bufplugin/descriptor"
)

// Annotation represents a rule Failure.
//
// An annotation always contains the ID of the Rule that failed. It also optionally
// contains a user-readable message, a location of the failure, and a location of the
// failure in the against FileDescriptors.
//
// Annotations are created on the server-side via ResponseWriters, and returned
// from Clients on Responses.
type Annotation interface {
	// RuleID is the ID of the Rule that failed.
	//
	// This will always be present.
	RuleID() string
	// Message is a user-readable message describing the failure.
	Message() string
	// FileLocation is the location of the failure.
	FileLocation() descriptor.FileLocation
	// AgainstFileLocation is the FileLocation of the failure in the against FileDescriptors.
	//
	// Will only potentially be produced for breaking change rules.
	AgainstFileLocation() descriptor.FileLocation

	toProto() *checkv1.Annotation

	isAnnotation()
}

// *** PRIVATE ***

type annotation struct {
	ruleID              string
	message             string
	fileLocation        descriptor.FileLocation
	againstFileLocation descriptor.FileLocation
}

func newAnnotation(
	ruleID string,
	message string,
	fileLocation descriptor.FileLocation,
	againstFileLocation descriptor.FileLocation,
) (*annotation, error) {
	if ruleID == "" {
		return nil, errors.New("check.Annotation: RuleID is empty")
	}
	return &annotation{
		ruleID:              ruleID,
		message:             message,
		fileLocation:        fileLocation,
		againstFileLocation: againstFileLocation,
	}, nil
}

func (a *annotation) RuleID() string {
	return a.ruleID
}

func (a *annotation) Message() string {
	return a.message
}

func (a *annotation) FileLocation() descriptor.FileLocation {
	return a.fileLocation
}

func (a *annotation) AgainstFileLocation() descriptor.FileLocation {
	return a.againstFileLocation
}

func (a *annotation) toProto() *checkv1.Annotation {
	if a == nil {
		return nil
	}
	var protoFileLocation *descriptorv1.FileLocation
	if a.fileLocation != nil {
		protoFileLocation = a.fileLocation.ToProto()
	}
	var protoAgainstFileLocation *descriptorv1.FileLocation
	if a.againstFileLocation != nil {
		protoAgainstFileLocation = a.againstFileLocation.ToProto()
	}
	return &checkv1.Annotation{
		RuleId:              a.RuleID(),
		Message:             a.Message(),
		FileLocation:        protoFileLocation,
		AgainstFileLocation: protoAgainstFileLocation,
	}
}

func (*annotation) isAnnotation() {}

func sortAnnotations(annotations []Annotation) {
	sort.Slice(
		annotations,
		func(i int, j int) bool {
			return CompareAnnotations(annotations[i], annotations[j]) < 0
		},
	)
}
