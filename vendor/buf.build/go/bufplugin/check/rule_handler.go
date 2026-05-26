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
	"context"
)

var nopRuleHandler = RuleHandlerFunc(func(context.Context, ResponseWriter, Request) error { return nil })

// RuleHandler implements the check logic for a single Rule.
//
// A RuleHandler takes in a Request, and writes Annotations to the ResponseWriter.
type RuleHandler interface {
	Handle(ctx context.Context, responseWriter ResponseWriter, request Request) error
}

// RuleHandlerFunc is a function that implements RuleHandler.
type RuleHandlerFunc func(context.Context, ResponseWriter, Request) error

// Handle implements RuleHandler.
func (r RuleHandlerFunc) Handle(ctx context.Context, responseWriter ResponseWriter, request Request) error {
	return r(ctx, responseWriter, request)
}
