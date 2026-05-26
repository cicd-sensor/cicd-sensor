// Copyright 2024 Buf Technologies, Inc.
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

package pluginrpc

import (
	"errors"
	"fmt"
	"strings"

	pluginrpcv1 "buf.build/gen/go/pluginrpc/pluginrpc/protocolbuffers/go/pluginrpc/v1"
)

// TODO: Figure out when and where to wrap errors created by this package with Errors.

// Error is an error with a Code.
type Error struct {
	code       Code
	underlying error
}

// NewError returns a new Error.
//
// Code and underlying with a non-empty message are required.
//
// An Error will never have an invalid Code or nil underlying error
// when returned from this function.
func NewError(code Code, underlying error) *Error {
	return validateError(
		&Error{
			code:       code,
			underlying: underlying,
		},
	)
}

// NewErrorf returns a new Error.

// Code and a non-empty message are required.
//
// An Error will never have an invalid Code or nil underlying error
// when returned from this function.
func NewErrorf(code Code, format string, args ...any) *Error {
	return NewError(code, fmt.Errorf(format, args...))
}

// NewErrorForProto returns a new Error for the given pluginrpcv1.Error.
//
// If protoError is nil, this returns nil.
func NewErrorForProto(protoError *pluginrpcv1.Error) *Error {
	if protoError == nil {
		return nil
	}
	code, err := CodeForProto(protoError.GetCode())
	if err != nil {
		return NewError(
			CodeInternal,
			fmt.Errorf("Error created with invalid code: %s: %w", protoError.GetMessage(), err),
		)
	}
	return NewError(
		code,
		errors.New(protoError.GetMessage()),
	)
}

// WrapError wraps the given error as a Error.
//
// If the given error is nil, this returns nil.
// If the given error is already a Error, this is returned.
// Otherwise, an error with code CodeUnknown is returned.
//
// An Error will never have an invalid Code when returned from this function.
func WrapError(err error) *Error {
	if err == nil {
		return nil
	}
	pluginrpcError := &Error{}
	if errors.As(err, &pluginrpcError) {
		return validateError(pluginrpcError)
	}
	return NewError(CodeUnknown, err)
}

// Code returns the error code.
//
// If e is nil, this returns 0.
func (e *Error) Code() Code {
	if e == nil {
		return Code(0)
	}
	return e.code
}

// ToProto converts the Error to a pluginrpcv1.Error.
//
// If e is nil, this returns nil.
func (e *Error) ToProto() *pluginrpcv1.Error {
	if e == nil {
		return nil
	}
	pluginrpcError := validateError(e)
	protoCode, err := pluginrpcError.Code().ToProto()
	if err != nil {
		return &pluginrpcv1.Error{
			Code:    pluginrpcv1.Code_CODE_INTERNAL,
			Message: fmt.Sprintf("Error created with invalid code: %s: %s", e.underlying.Error(), err.Error()),
		}
	}
	return &pluginrpcv1.Error{
		Code:    protoCode,
		Message: pluginrpcError.Unwrap().Error(),
	}
}

// Error implements error.
//
// If e is nil, this returns the empty string.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	var sb strings.Builder
	_, _ = sb.WriteString(`Failed with code `)
	_, _ = sb.WriteString(e.code.String())
	if e.underlying != nil {
		_, _ = sb.WriteString(`: `)
		_, _ = sb.WriteString(e.underlying.Error())
	}
	return sb.String()
}

// Unwrap implements error.
//
// If e is nil, this returns nil.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.underlying
}

// *** PRIVATE ***

func validateError(pluginrpcError *Error) *Error {
	code := pluginrpcError.Code()
	underlying := pluginrpcError.Unwrap()
	if !isValidCode(code) {
		return newInvalidCodeError(pluginrpcError)
	}
	if underlying == nil {
		return newNilUnderlyingError(pluginrpcError)
	}
	if underlyingString := underlying.Error(); underlyingString == "" {
		return newEmptyUnderlyingError(pluginrpcError)
	}
	return pluginrpcError
}

func newInvalidCodeError(pluginrpcError *Error) *Error {
	return &Error{
		code:       CodeInternal,
		underlying: fmt.Errorf("Error created with code %v: %w", pluginrpcError.Code(), pluginrpcError.Unwrap()),
	}
}

func newNilUnderlyingError(pluginrpcError *Error) *Error {
	return &Error{
		code:       CodeInternal,
		underlying: fmt.Errorf("Error created with code %v and nil underlying error", pluginrpcError.Code()),
	}
}

func newEmptyUnderlyingError(pluginrpcError *Error) *Error {
	return &Error{
		code:       CodeInternal,
		underlying: fmt.Errorf("Error created with code %v and empty underlying error", pluginrpcError.Code()),
	}
}
