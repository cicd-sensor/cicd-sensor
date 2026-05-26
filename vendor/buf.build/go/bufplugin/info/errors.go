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
	"errors"
	"fmt"
	"strings"
)

type validateSpecError struct {
	delegate error
}

func newValidateSpecError(message string) *validateSpecError {
	return &validateSpecError{
		delegate: errors.New(message),
	}
}

func newValidateSpecErrorf(format string, args ...any) *validateSpecError {
	return &validateSpecError{
		delegate: fmt.Errorf(format, args...),
	}
}

func (vr *validateSpecError) Error() string {
	if vr == nil {
		return ""
	}
	if vr.delegate == nil {
		return ""
	}
	var sb strings.Builder
	_, _ = sb.WriteString(`invalid info.Spec: `)
	_, _ = sb.WriteString(vr.delegate.Error())
	return sb.String()
}

func (vr *validateSpecError) Unwrap() error {
	if vr == nil {
		return nil
	}
	return vr.delegate
}
