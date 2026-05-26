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

package protopluginutil

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	fileMessagesTag           = 4
	fileEnumsTag              = 5
	fileServicesTag           = 6
	fileExtensionsTag         = 7
	fileOptionsTag            = 8
	messageFieldsTag          = 2
	messageNestedMessagesTag  = 3
	messageEnumsTag           = 4
	messageExtensionRangesTag = 5
	messageExtensionsTag      = 6
	messageOptionsTag         = 7
	messageOneofsTag          = 8
	extensionRangeOptionsTag  = 3
	fieldOptionsTag           = 8
	oneofOptionsTag           = 2
	enumValuesTag             = 2
	enumOptionsTag            = 3
	enumValOptionsTag         = 3
	serviceMethodsTag         = 2
	serviceOptionsTag         = 3
	methodOptionsTag          = 4
)

// StripSourceRetentionOptions returns a FileDescriptorProto that omits any source-retention options.

// If the FileDescriptorProto has no source-retention options, the original FileDescriptorProto is returned.
// If the FileDescriptorProto has source-retention options, a new FileDescriptorProto is returned with
// the source-retention options stripped.
//
// Even when a copy is returned, it is not a deep copy: it may share data with the
// input FileDescriptorProto, and mutations to the returned FileDescriptorProto may impact
// the input FileDescriptorProto.
func StripSourceRetentionOptions(file *descriptorpb.FileDescriptorProto) (*descriptorpb.FileDescriptorProto, error) {
	var path sourcePath
	var removedPaths *sourcePathTrie
	if file.GetSourceCodeInfo() != nil && len(file.GetSourceCodeInfo().GetLocation()) > 0 {
		path = make(sourcePath, 0, 16)
		removedPaths = &sourcePathTrie{}
	}
	var dirty bool
	optionsPath := path.push(fileOptionsTag)
	newOpts, err := stripSourceRetentionOptionsFromProtoMessage(file.GetOptions(), optionsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if newOpts != file.GetOptions() {
		dirty = true
	}
	msgsPath := path.push(fileMessagesTag)
	newMsgs, changed, err := stripOptionsFromAll(file.GetMessageType(), stripSourceRetentionOptionsFromMessage, msgsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}
	enumsPath := path.push(fileEnumsTag)
	newEnums, changed, err := stripOptionsFromAll(file.GetEnumType(), stripSourceRetentionOptionsFromEnum, enumsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}
	extsPath := path.push(fileExtensionsTag)
	newExts, changed, err := stripOptionsFromAll(file.GetExtension(), stripSourceRetentionOptionsFromField, extsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}
	svcsPath := path.push(fileServicesTag)
	newSvcs, changed, err := stripOptionsFromAll(file.GetService(), stripSourceRetentionOptionsFromService, svcsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}

	if !dirty {
		return file, nil
	}

	newFile, err := shallowCopy(file)
	if err != nil {
		return nil, err
	}
	newFile.Options = newOpts
	newFile.MessageType = newMsgs
	newFile.EnumType = newEnums
	newFile.Extension = newExts
	newFile.Service = newSvcs
	newFile.SourceCodeInfo = stripSourcePathsForSourceRetentionOptions(newFile.GetSourceCodeInfo(), removedPaths)
	return newFile, nil
}

func stripSourceRetentionOptionsFromProtoMessage[M proto.Message](
	options M,
	path sourcePath,
	removedPaths *sourcePathTrie,
) (M, error) {
	optionsRef := options.ProtoReflect()
	// See if there are any options to strip.
	var hasFieldToStrip bool
	var numFieldsToKeep int
	var err error
	optionsRef.Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		fieldOpts, ok := field.Options().(*descriptorpb.FieldOptions)
		if !ok {
			err = fmt.Errorf("field options is unexpected type: got %T, want %T", field.Options(), fieldOpts)
			return false
		}
		if fieldOpts.GetRetention() == descriptorpb.FieldOptions_RETENTION_SOURCE {
			hasFieldToStrip = true
		} else {
			numFieldsToKeep++
		}
		return true
	})
	var zero M
	if err != nil {
		return zero, err
	}
	if !hasFieldToStrip {
		return options, nil
	}

	if numFieldsToKeep == 0 {
		// Stripping the message would remove *all* options. In that case,
		// we'll clear out the options by returning the zero value (i.e. nil).
		removedPaths.addPath(path) // clear out all source locations, too
		return zero, nil
	}

	// There is at least one option to remove. So we need to make a copy that does not have those options.
	newOptions := optionsRef.New()
	ret, ok := newOptions.Interface().(M)
	if !ok {
		return zero, fmt.Errorf("creating new message of same type resulted in unexpected type; got %T, want %T", newOptions.Interface(), zero)
	}
	optionsRef.Range(func(field protoreflect.FieldDescriptor, val protoreflect.Value) bool {
		fieldOpts, ok := field.Options().(*descriptorpb.FieldOptions)
		if !ok {
			err = fmt.Errorf("field options is unexpected type: got %T, want %T", field.Options(), fieldOpts)
			return false
		}
		if fieldOpts.GetRetention() != descriptorpb.FieldOptions_RETENTION_SOURCE {
			newOptions.Set(field, val)
		} else {
			removedPaths.addPath(path.push(int32(field.Number())))
		}
		return true
	})
	if err != nil {
		return zero, err
	}
	return ret, nil
}

func stripSourceRetentionOptionsFromMessage(
	msg *descriptorpb.DescriptorProto,
	path sourcePath,
	removedPaths *sourcePathTrie,
) (*descriptorpb.DescriptorProto, error) {
	var dirty bool
	optionsPath := path.push(messageOptionsTag)
	newOpts, err := stripSourceRetentionOptionsFromProtoMessage(msg.GetOptions(), optionsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if newOpts != msg.GetOptions() {
		dirty = true
	}
	fieldsPath := path.push(messageFieldsTag)
	newFields, changed, err := stripOptionsFromAll(msg.GetField(), stripSourceRetentionOptionsFromField, fieldsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}
	oneofsPath := path.push(messageOneofsTag)
	newOneofs, changed, err := stripOptionsFromAll(msg.GetOneofDecl(), stripSourceRetentionOptionsFromOneof, oneofsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}
	extRangesPath := path.push(messageExtensionRangesTag)
	newExtRanges, changed, err := stripOptionsFromAll(msg.GetExtensionRange(), stripSourceRetentionOptionsFromExtensionRange, extRangesPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}
	msgsPath := path.push(messageNestedMessagesTag)
	newMsgs, changed, err := stripOptionsFromAll(msg.GetNestedType(), stripSourceRetentionOptionsFromMessage, msgsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}
	enumsPath := path.push(messageEnumsTag)
	newEnums, changed, err := stripOptionsFromAll(msg.GetEnumType(), stripSourceRetentionOptionsFromEnum, enumsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}
	extsPath := path.push(messageExtensionsTag)
	newExts, changed, err := stripOptionsFromAll(msg.GetExtension(), stripSourceRetentionOptionsFromField, extsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}

	if !dirty {
		return msg, nil
	}

	newMsg, err := shallowCopy(msg)
	if err != nil {
		return nil, err
	}
	newMsg.Options = newOpts
	newMsg.Field = newFields
	newMsg.OneofDecl = newOneofs
	newMsg.ExtensionRange = newExtRanges
	newMsg.NestedType = newMsgs
	newMsg.EnumType = newEnums
	newMsg.Extension = newExts
	return newMsg, nil
}

func stripSourceRetentionOptionsFromField(
	field *descriptorpb.FieldDescriptorProto,
	path sourcePath,
	removedPaths *sourcePathTrie,
) (*descriptorpb.FieldDescriptorProto, error) {
	optionsPath := path.push(fieldOptionsTag)
	newOpts, err := stripSourceRetentionOptionsFromProtoMessage(field.GetOptions(), optionsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if newOpts == field.GetOptions() {
		return field, nil
	}
	newField, err := shallowCopy(field)
	if err != nil {
		return nil, err
	}
	newField.Options = newOpts
	return newField, nil
}

func stripSourceRetentionOptionsFromOneof(
	oneof *descriptorpb.OneofDescriptorProto,
	path sourcePath,
	removedPaths *sourcePathTrie,
) (*descriptorpb.OneofDescriptorProto, error) {
	optionsPath := path.push(oneofOptionsTag)
	newOpts, err := stripSourceRetentionOptionsFromProtoMessage(oneof.GetOptions(), optionsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if newOpts == oneof.GetOptions() {
		return oneof, nil
	}
	newOneof, err := shallowCopy(oneof)
	if err != nil {
		return nil, err
	}
	newOneof.Options = newOpts
	return newOneof, nil
}

func stripSourceRetentionOptionsFromExtensionRange(
	extRange *descriptorpb.DescriptorProto_ExtensionRange,
	path sourcePath,
	removedPaths *sourcePathTrie,
) (*descriptorpb.DescriptorProto_ExtensionRange, error) {
	optionsPath := path.push(extensionRangeOptionsTag)
	newOpts, err := stripSourceRetentionOptionsFromProtoMessage(extRange.GetOptions(), optionsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if newOpts == extRange.GetOptions() {
		return extRange, nil
	}
	newExtRange, err := shallowCopy(extRange)
	if err != nil {
		return nil, err
	}
	newExtRange.Options = newOpts
	return newExtRange, nil
}

func stripSourceRetentionOptionsFromEnum(
	enum *descriptorpb.EnumDescriptorProto,
	path sourcePath,
	removedPaths *sourcePathTrie,
) (*descriptorpb.EnumDescriptorProto, error) {
	var dirty bool
	optionsPath := path.push(enumOptionsTag)
	newOpts, err := stripSourceRetentionOptionsFromProtoMessage(enum.GetOptions(), optionsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if newOpts != enum.GetOptions() {
		dirty = true
	}
	valsPath := path.push(enumValuesTag)
	newVals, changed, err := stripOptionsFromAll(enum.GetValue(), stripSourceRetentionOptionsFromEnumValue, valsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}

	if !dirty {
		return enum, nil
	}

	newEnum, err := shallowCopy(enum)
	if err != nil {
		return nil, err
	}
	newEnum.Options = newOpts
	newEnum.Value = newVals
	return newEnum, nil
}

func stripSourceRetentionOptionsFromEnumValue(
	enumVal *descriptorpb.EnumValueDescriptorProto,
	path sourcePath,
	removedPaths *sourcePathTrie,
) (*descriptorpb.EnumValueDescriptorProto, error) {
	optionsPath := path.push(enumValOptionsTag)
	newOpts, err := stripSourceRetentionOptionsFromProtoMessage(enumVal.GetOptions(), optionsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if newOpts == enumVal.GetOptions() {
		return enumVal, nil
	}
	newEnumVal, err := shallowCopy(enumVal)
	if err != nil {
		return nil, err
	}
	newEnumVal.Options = newOpts
	return newEnumVal, nil
}

func stripSourceRetentionOptionsFromService(
	svc *descriptorpb.ServiceDescriptorProto,
	path sourcePath,
	removedPaths *sourcePathTrie,
) (*descriptorpb.ServiceDescriptorProto, error) {
	var dirty bool
	optionsPath := path.push(serviceOptionsTag)
	newOpts, err := stripSourceRetentionOptionsFromProtoMessage(svc.GetOptions(), optionsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if newOpts != svc.GetOptions() {
		dirty = true
	}
	methodsPath := path.push(serviceMethodsTag)
	newMethods, changed, err := stripOptionsFromAll(svc.GetMethod(), stripSourceRetentionOptionsFromMethod, methodsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if changed {
		dirty = true
	}

	if !dirty {
		return svc, nil
	}

	newSvc, err := shallowCopy(svc)
	if err != nil {
		return nil, err
	}
	newSvc.Options = newOpts
	newSvc.Method = newMethods
	return newSvc, nil
}

func stripSourceRetentionOptionsFromMethod(
	method *descriptorpb.MethodDescriptorProto,
	path sourcePath,
	removedPaths *sourcePathTrie,
) (*descriptorpb.MethodDescriptorProto, error) {
	optionsPath := path.push(methodOptionsTag)
	newOpts, err := stripSourceRetentionOptionsFromProtoMessage(method.GetOptions(), optionsPath, removedPaths)
	if err != nil {
		return nil, err
	}
	if newOpts == method.GetOptions() {
		return method, nil
	}
	newMethod, err := shallowCopy(method)
	if err != nil {
		return nil, err
	}
	newMethod.Options = newOpts
	return newMethod, nil
}

func stripSourcePathsForSourceRetentionOptions(
	sourceInfo *descriptorpb.SourceCodeInfo,
	removedPaths *sourcePathTrie,
) *descriptorpb.SourceCodeInfo {
	if sourceInfo == nil || len(sourceInfo.GetLocation()) == 0 || removedPaths == nil {
		// nothing to do
		return sourceInfo
	}
	newLocations := make([]*descriptorpb.SourceCodeInfo_Location, len(sourceInfo.GetLocation()))
	var i int
	for _, loc := range sourceInfo.GetLocation() {
		if removedPaths.isRemoved(loc.GetPath()) {
			continue
		}
		newLocations[i] = loc
		i++
	}
	newLocations = newLocations[:i]
	return &descriptorpb.SourceCodeInfo{Location: newLocations}
}

func shallowCopy[M proto.Message](msg M) (M, error) {
	msgRef := msg.ProtoReflect()
	other := msgRef.New()
	ret, ok := other.Interface().(M)
	if !ok {
		return ret, fmt.Errorf("creating new message of same type resulted in unexpected type; got %T, want %T", other.Interface(), ret)
	}
	msgRef.Range(func(field protoreflect.FieldDescriptor, val protoreflect.Value) bool {
		other.Set(field, val)
		return true
	})
	return ret, nil
}

// stripOptionsFromAll applies the given function to each element in the given
// slice in order to remove source-retention options from it. It returns the new
// slice and a bool indicating whether anything was actually changed. If the
// second value is false, then the returned slice is the same slice as the input
// slice. Usually, T is a pointer type, in which case the given updateFunc should
// NOT mutate the input value. Instead, it should return the input value if only
// if there is no update needed. If a mutation is needed, it should return a new
// value.
func stripOptionsFromAll[T comparable](
	slice []T,
	updateFunc func(T, sourcePath, *sourcePathTrie) (T, error),
	path sourcePath,
	removedPaths *sourcePathTrie,
) ([]T, bool, error) {
	var updated []T // initialized lazily, only when/if a copy is needed
	for i, item := range slice {
		index := int32(i) // #nosec:G115 should never overflow
		newItem, err := updateFunc(item, path.push(index), removedPaths)
		if err != nil {
			return nil, false, err
		}
		if updated != nil {
			updated[i] = newItem
		} else if newItem != item {
			updated = make([]T, len(slice))
			copy(updated[:i], slice)
			updated[i] = newItem
		}
	}
	if updated != nil {
		return updated, true, nil
	}
	return slice, false, nil
}

type sourcePath protoreflect.SourcePath

func (p sourcePath) push(element int32) sourcePath {
	if p == nil {
		return nil
	}
	return append(p, element)
}

type sourcePathTrie struct {
	removed  bool
	children map[int32]*sourcePathTrie
}

func (t *sourcePathTrie) addPath(path sourcePath) {
	if t == nil {
		return
	}
	if len(path) == 0 {
		t.removed = true
		return
	}
	child := t.children[path[0]]
	if child == nil {
		if t.children == nil {
			t.children = map[int32]*sourcePathTrie{}
		}
		child = &sourcePathTrie{}
		t.children[path[0]] = child
	}
	child.addPath(path[1:])
}

func (t *sourcePathTrie) isRemoved(path []int32) bool {
	if t == nil {
		return false
	}
	if t.removed {
		return true
	}
	if len(path) == 0 {
		return false
	}
	child := t.children[path[0]]
	if child == nil {
		return false
	}
	return child.isRemoved(path[1:])
}
