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
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

const allSupportedFeaturesMask = uint64(
	pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL |
		pluginpb.CodeGeneratorResponse_FEATURE_SUPPORTS_EDITIONS,
)

// validateCodeGeneratorRequest validates that the CodeGeneratorRequest conforms to the following:
//
//   - The CodeGeneratorRequest will not be nil.
//   - file_to_generate and proto_file will be non-empty.
//   - Each FileDescriptorProto in proto_file and source_file_descriptors will have valid paths
//     as the name and dependency fields.
//   - Each FileDescriptorProto in proto_file and source_file_descriptors will have unique name fields.
//   - Each FileDescriptorProto in proto_file and source_file_descriptors will have unique values of their
//     dependency fields, that is there will be no duplicates within a single FileDescriptorProto.
//   - source_file_descriptors is either empty, or the values of file_to_generate will have a 1-1 mapping
//     to the names in source_file_descriptors.
//   - Each value of file_to_generate will be a valid path.
//   - Each value of file_to_generate will have a corresponding value in proto_file.
//   - The major, minor, and patch versions of compiler_version will be non-negative.
//
// Paths are considered valid if they are non-empty, relative, use '/' as the path separator, do not jump context,
// and have `.proto` as the file extension.
func validateCodeGeneratorRequest(request *pluginpb.CodeGeneratorRequest) (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("CodeGeneratorRequest: %w", retErr)
		}
	}()

	if request == nil {
		return errors.New("nil")
	}
	if len(request.GetProtoFile()) == 0 {
		return errors.New("proto_file: empty")
	}
	if len(request.GetFileToGenerate()) == 0 {
		return errors.New("file_to_generate: empty")
	}
	if err := validateAndCheckProtoPathsAreNormalized("file_to_generate", request.GetFileToGenerate()); err != nil {
		return err
	}
	if err := validateCodeGeneratorRequestFileDescriptorProtos(
		"proto_file",
		request.GetProtoFile(),
		request.GetFileToGenerate(),
		false,
	); err != nil {
		return err
	}
	if len(request.GetSourceFileDescriptors()) > 0 {
		if err := validateCodeGeneratorRequestFileDescriptorProtos(
			"source_file_descriptors",
			request.GetSourceFileDescriptors(),
			request.GetFileToGenerate(),
			true,
		); err != nil {
			return err
		}
	}
	if version := request.GetCompilerVersion(); version != nil {
		if err := validateCompilerVersion(version); err != nil {
			return fmt.Errorf("compiler_version: %w", err)
		}
	}
	return nil
}

func validateCodeGeneratorRequestFileDescriptorProtos(
	fieldName string,
	fileDescriptorProtos []*descriptorpb.FileDescriptorProto,
	filesToGenerate []string,
	// If true, the FileDescriptorProto Names should be equal to the names in filesToGenerate.
	// If false, the FileDescriptorProto Names should be a superset of the names in filesToGenerate.
	// This is true for source_file_descriptors, false for proto_file.
	equalToOrSupersetOfFilesToGenerate bool,
) error {
	fileDescriptorProtoNameMap := make(map[string]struct{}, len(fileDescriptorProtos))
	for _, fileDescriptorProto := range fileDescriptorProtos {
		if err := validateFileDescriptorProto(fieldName, fileDescriptorProto); err != nil {
			return err
		}
		fileDescriptorProtoName := fileDescriptorProto.GetName()
		if _, ok := fileDescriptorProtoNameMap[fileDescriptorProtoName]; ok {
			return fmt.Errorf("%s: duplicate path %q", fieldName, fileDescriptorProtoName)
		}
		fileDescriptorProtoNameMap[fileDescriptorProtoName] = struct{}{}
	}
	for _, fileToGenerate := range filesToGenerate {
		if _, ok := fileDescriptorProtoNameMap[fileToGenerate]; !ok {
			return fmt.Errorf("file_to_generate: path %q is not contained within %s", fileToGenerate, fieldName)
		}
	}
	if equalToOrSupersetOfFilesToGenerate {
		// Since we already checked if fileDescriptorProtoNameMap contains filesToGenerate, if
		// filesToGenerate contains fileDescriptorProtoNameMap, we are equal.
		filesToGenerateMap := make(map[string]struct{}, len(filesToGenerate))
		for _, fileToGenerate := range filesToGenerate {
			filesToGenerateMap[fileToGenerate] = struct{}{}
		}
		for fileDescriptorProtoName := range fileDescriptorProtoNameMap {
			if _, ok := filesToGenerateMap[fileDescriptorProtoName]; !ok {
				return fmt.Errorf("%s: path %q is not contained within file_to_generate", fieldName, fileDescriptorProtoName)
			}
		}
	}
	return nil
}

func validateCompilerVersion(version *pluginpb.Version) error {
	if major := version.GetMajor(); major < 0 {
		return fmt.Errorf("major: negative: %d", int(major))
	}
	if minor := version.GetMinor(); minor < 0 {
		return fmt.Errorf("minor: negative: %d", int(minor))
	}
	if patch := version.GetPatch(); patch < 0 {
		return fmt.Errorf("patch: negative: %d", int(patch))
	}
	return nil
}

func validateAndNormalizeCodeGeneratorResponse(
	response *pluginpb.CodeGeneratorResponse,
	// Non-nil if non-critical errors should be warnings instead of errors.
	//
	// If not set, no modifications will be performed.
	lenientResponseValidateErrorFunc func(error),
) (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("CodeGeneratorResponse: %w", retErr)
		}
	}()

	files, err := validateAndNormalizeCodeGeneratorResponseFilesWithPotentialEmptyNames("file", response.File)
	if err != nil {
		return err
	}
	// Avoid unnecessary modifications of response.File in the case where we had no difference.
	if len(response.File) != len(files) {
		response.File = files
	}
	files, err = validateAndNormalizeCodeGeneratorResponseFilesWithPotentialDuplicates("file", response.File, lenientResponseValidateErrorFunc)
	if err != nil {
		return err
	}
	// Avoid unnecessary modifications of response.File in the case where we had no difference.
	if len(response.File) != len(files) {
		response.File = files
	}

	if response.GetSupportedFeatures()|allSupportedFeaturesMask != allSupportedFeaturesMask {
		return fmt.Errorf("supported_features: unknown CodeGeneratorResponse.Features: %s", strconv.FormatUint(response.GetSupportedFeatures(), 2))
	}
	if response.GetSupportedFeatures()&uint64(pluginpb.CodeGeneratorResponse_FEATURE_SUPPORTS_EDITIONS) != 0 {
		if response.GetMinimumEdition() == 0 {
			return errors.New("supported_features: FEATURE_SUPPORTS_EDITIONS specified but no minimum_edition set")
		}
		if response.GetMaximumEdition() == 0 {
			return errors.New("supported_features: FEATURE_SUPPORTS_EDITIONS specified but no maximum_edition set")
		}
		if response.GetMinimumEdition() > response.GetMaximumEdition() {
			return fmt.Errorf(
				"minimum_edition %d is greater than maximum_edition %d",
				response.GetMinimumEdition(),
				response.GetMaximumEdition(),
			)
		}
	}
	return nil
}

// validateAndNormalizeCodeGeneratorResponseFilesWithPotentialEmptyNames normalized all
// CodeGeneratorResponse_Files such that every file has a name.
//
// The spec of CodeGeneratorResponse says that if you have files without names or insertion points,
// to append them to the previous file. However, it also says this feature is never used, and it is
// for a theoretical streaming feature of CodeGeneratorResponses. In essence, this functionality
// serves no purpose, and we have normalized these responses in buf for years with no issue.
func validateAndNormalizeCodeGeneratorResponseFilesWithPotentialEmptyNames(
	fieldName string,
	files []*pluginpb.CodeGeneratorResponse_File,
) ([]*pluginpb.CodeGeneratorResponse_File, error) {
	if len(files) == 0 {
		return files, nil
	}

	prevFile := files[0]
	if prevFile.GetName() == "" {
		// This is always an error.
		return nil, fmt.Errorf("%s: first value had no name set", fieldName)
	}
	// If we only have one file, just return it.
	if len(files) == 1 {
		return files, nil
	}

	resultFiles := make([]*pluginpb.CodeGeneratorResponse_File, 0, len(files))
	var curFile *pluginpb.CodeGeneratorResponse_File
	for i := 1; i < len(files); i++ {
		curFile = files[i]
		name := curFile.GetName()
		insertionPoint := curFile.GetInsertionPoint()
		if name != "" {
			// If the name is non-empty, append prev to the result.
			resultFiles = append(resultFiles, prevFile)
			prevFile = curFile
		} else {
			if insertionPoint != "" {
				// If insertion point is non-empty but the name is empty, this is an error.
				return nil, fmt.Errorf("%s: empty name with non-empty insertion point", fieldName)
			}
			if curFile.Content != nil {
				if prevFile.Content == nil {
					prevFile.Content = curFile.Content
				} else {
					prevFile.Content = proto.String(
						prevFile.GetContent() + curFile.GetContent(),
					)
				}
			}
		}
		// If we are at the end of the loop, add the file, as we
		// will not hit the beginning of the loop again.
		if i == len(files)-1 {
			resultFiles = append(resultFiles, prevFile)
		}
	}
	return resultFiles, nil
}

// Must be called after validateAndNormalizeCodeGeneratorResponseFilesWithPotentialEmptyNames.
//
// This function relies on the fact that no file has an empty name.
func validateAndNormalizeCodeGeneratorResponseFilesWithPotentialDuplicates(
	fieldName string,
	files []*pluginpb.CodeGeneratorResponse_File,
	// Non-nil if non-critical errors should be warnings instead of errors.
	lenientResponseValidateErrorFunc func(error),
) ([]*pluginpb.CodeGeneratorResponse_File, error) {
	fileNameToFile := make(map[string]*pluginpb.CodeGeneratorResponse_File)
	resultFiles := make([]*pluginpb.CodeGeneratorResponse_File, 0, len(files))
	for _, file := range files {
		name := file.GetName()
		insertionPoint := file.GetInsertionPoint()
		content := file.GetContent()
		normalizedName, err := validateAndNormalizePath(fieldName, name)
		if err != nil {
			return nil, err
		}
		if name != normalizedName {
			if lenientResponseValidateErrorFunc != nil {
				lenientResponseValidateErrorFunc(newUnnormalizedCodeGeneratorResponseFileNameError(name, normalizedName, true))
				// We will coerce this into a normalized name if it is otherwise valid.
				name = normalizedName
				file.Name = proto.String(name)
			} else {
				return nil, fmt.Errorf("%s: %w", fieldName, newUnnormalizedCodeGeneratorResponseFileNameError(name, normalizedName, false))
			}
		}
		// If insertionPoint is set, it is valid and correct to have a duplicate file.
		if otherFile, ok := fileNameToFile[name]; ok && insertionPoint == "" {
			if otherFile.GetContent() != content {
				if lenientResponseValidateErrorFunc != nil {
					lenientResponseValidateErrorFunc(newDuplicateCodeGeneratorResponseFileNameError(name, true))
				} else {
					return nil, fmt.Errorf("%s: %w", fieldName, newDuplicateCodeGeneratorResponseFileNameError(name, false))
				}
			}
		} else {
			// Not a duplicate, add to result files.
			resultFiles = append(resultFiles, file)
			fileNameToFile[name] = file
		}
	}
	return resultFiles, nil
}

func validateFileDescriptorProto(fieldName string, fileDescriptorProto *descriptorpb.FileDescriptorProto) error {
	if fileDescriptorProto == nil {
		return fmt.Errorf("%s: nil", fieldName)
	}
	if err := validateAndCheckProtoPathIsNormalized(fieldName+".name", fileDescriptorProto.GetName()); err != nil {
		return err
	}
	if err := validateAndCheckProtoPathsAreNormalized(fieldName+".dependency", fileDescriptorProto.GetDependency()); err != nil {
		return err
	}
	return nil
}

// validateAndCheckProtoPathsAreNormalized validates with validateProtoPaths, and ensures that the paths are unique.
func validateAndCheckProtoPathsAreNormalized(fieldName string, paths []string) error {
	pathMap := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if err := validateAndCheckProtoPathIsNormalized(fieldName, path); err != nil {
			return err
		}
		if _, ok := pathMap[path]; ok {
			return fmt.Errorf("%s: duplicate path %q", fieldName, path)
		}
		pathMap[path] = struct{}{}
	}
	return nil
}

// validateAndCheckProtoPathIsNormalized validates that the path is non-empty, relative, uses '/' as the
// path separator, is equal to filepath.ToSlash(filepath.Clean(path)),
// and has .proto as the file extension.
func validateAndCheckProtoPathIsNormalized(fieldName string, path string) error {
	if err := validateAndCheckPathIsNormalized(fieldName, path); err != nil {
		return err
	}
	if filepath.Ext(path) != ".proto" {
		return fmt.Errorf("%s: path %q should have the .proto file extension", fieldName, path)
	}
	return nil
}

// validateCheckPathIsNormalized validates that the path is non-empty, relative, and uses '/' as the
// path separator, and is equal to filepath.ToSlash(filepath.Clean(path)).
func validateAndCheckPathIsNormalized(fieldName string, path string) error {
	normalizedPath, err := validateAndNormalizePath(fieldName, path)
	if err != nil {
		return err
	}
	if path != normalizedPath {
		return fmt.Errorf("%s: path %q to be given as %q", fieldName, path, normalizedPath)
	}
	return nil
}

// validateAndNormalizePath validates that the path is non-empty, relative, and uses '/' as the
// path separator, and returns filepath.ToSlash(filepath.Clean(path)). It does not
// validate that the path is equal to the normalized value.
func validateAndNormalizePath(fieldName string, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s: path was empty", fieldName)
	}
	normalizedPath := filepath.ToSlash(filepath.Clean(path))
	if filepath.IsAbs(normalizedPath) {
		return "", fmt.Errorf("%s: path %q should be relative", fieldName, normalizedPath)
	}
	// https://github.com/bufbuild/buf/issues/51
	if strings.HasPrefix(normalizedPath, "../") {
		return "", fmt.Errorf("%s: path %q should not jump context", fieldName, normalizedPath)
	}
	return normalizedPath, nil
}
