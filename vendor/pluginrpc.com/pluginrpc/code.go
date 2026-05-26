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
	"fmt"

	pluginrpcv1 "buf.build/gen/go/pluginrpc/pluginrpc/protocolbuffers/go/pluginrpc/v1"
)

// Code is an error code. There are no user-defined codes, so only the codes
// enumerated below are valid. In both name and semantics, these codes match the gRPC status codes.
type Code uint32

const (
	// The zero code in gRPC is OK, which indicates that the operation was a
	// success. We don't define a constant for it because it overlaps awkwardly
	// with Go's error semantics: what does it mean to have a non-nil error with
	// an OK status?

	// CodeCanceled indicates that the operation was canceled, typically by the
	// caller.
	CodeCanceled Code = 1

	// CodeUnknown indicates that the operation failed for an unknown reason.
	CodeUnknown Code = 2

	// CodeInvalidArgument indicates that client supplied an invalid argument.
	CodeInvalidArgument Code = 3

	// CodeDeadlineExceeded indicates that deadline expired before the operation
	// could complete.
	CodeDeadlineExceeded Code = 4

	// CodeNotFound indicates that some requested entity (for example, a file or
	// directory) was not found.
	CodeNotFound Code = 5

	// CodeAlreadyExists indicates that client attempted to create an entity (for
	// example, a file or directory) that already exists.
	CodeAlreadyExists Code = 6

	// CodePermissionDenied indicates that the caller doesn't have permission to
	// execute the specified operation.
	CodePermissionDenied Code = 7

	// CodeResourceExhausted indicates that some resource has been exhausted. For
	// example, a per-user quota may be exhausted or the entire file system may
	// be full.
	CodeResourceExhausted Code = 8

	// CodeFailedPrecondition indicates that the system is not in a state
	// required for the operation's execution.
	CodeFailedPrecondition Code = 9

	// CodeAborted indicates that operation was aborted by the system, usually
	// because of a concurrency issue such as a sequencer check failure or
	// transaction abort.
	CodeAborted Code = 10

	// CodeOutOfRange indicates that the operation was attempted past the valid
	// range (for example, seeking past end-of-file).
	CodeOutOfRange Code = 11

	// CodeUnimplemented indicates that the operation isn't implemented,
	// supported, or enabled in this service.
	CodeUnimplemented Code = 12

	// CodeInternal indicates that some invariants expected by the underlying
	// system have been broken. This code is reserved for serious errors.
	CodeInternal Code = 13

	// CodeUnavailable indicates that the service is currently unavailable. This
	// is usually temporary, so clients can back off and retry idempotent
	// operations.
	CodeUnavailable Code = 14

	// CodeDataLoss indicates that the operation has resulted in unrecoverable
	// data loss or corruption.
	CodeDataLoss Code = 15

	// CodeUnauthenticated indicates that the request does not have valid
	// authentication credentials for the operation.
	CodeUnauthenticated Code = 16

	minCode = CodeCanceled
	maxCode = CodeUnauthenticated
)

// String implements fmt.Stringer.
func (c Code) String() string {
	switch c {
	case CodeCanceled:
		return "canceled"
	case CodeUnknown:
		return "unknown"
	case CodeInvalidArgument:
		return "invalid_argument"
	case CodeDeadlineExceeded:
		return "deadline_exceeded"
	case CodeNotFound:
		return "not_found"
	case CodeAlreadyExists:
		return "already_exists"
	case CodePermissionDenied:
		return "permission_denied"
	case CodeResourceExhausted:
		return "resource_exhausted"
	case CodeFailedPrecondition:
		return "failed_precondition"
	case CodeAborted:
		return "aborted"
	case CodeOutOfRange:
		return "out_of_range"
	case CodeUnimplemented:
		return "unimplemented"
	case CodeInternal:
		return "internal"
	case CodeUnavailable:
		return "unavailable"
	case CodeDataLoss:
		return "data_loss"
	case CodeUnauthenticated:
		return "unauthenticated"
	}
	return fmt.Sprintf("code_%d", c)
}

// ToProto returns the pluginrpcv1.Code for the given Code.
//
// Returns error if the Code is not valid.
func (c Code) ToProto() (pluginrpcv1.Code, error) {
	if isValidCode(c) {
		return pluginrpcv1.Code(c), nil
	}
	return 0, fmt.Errorf("unknown Code: %v", c)
}

// CodeForProto returns the Code for the pluginrpcv1.Code.
//
// Returns error the pluginrpcv1.Code is not valid.
func CodeForProto(protoCode pluginrpcv1.Code) (Code, error) {
	if code := Code(protoCode); isValidCode(code) {
		return code, nil
	}
	return 0, fmt.Errorf("unknown pluginrpcv1.Code: %v", protoCode)
}

// *** PRIVATE ***

func isValidCode(code Code) bool {
	return code >= minCode && code <= maxCode
}
