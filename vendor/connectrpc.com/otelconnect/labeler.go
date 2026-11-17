// Copyright 2022-2025 The Connect Authors
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

package otelconnect

import (
	"context"
	"slices"
	"sync"

	"go.opentelemetry.io/otel/attribute"
)

// Labeler is used to allow instrumented ConnectRPC handlers to add custom
// attributes to the metrics recorded by the instrumentation.
type Labeler struct {
	mu         sync.Mutex
	attributes []attribute.KeyValue
}

// Add attributes to a Labeler.
func (l *Labeler) Add(ls ...attribute.KeyValue) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attributes = append(l.attributes, ls...)
}

// Get returns a copy of the attributes added to the Labeler.
func (l *Labeler) Get() []attribute.KeyValue {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.attributes)
}

type labelerContextKey struct{}

// ContextWithLabeler returns a new context with the provided Labeler instance.
// Attributes added to the specified labeler will be injected into metrics
// emitted by the instrumentation. Only one labeler can be injected into the
// context. Injecting it multiple times will override the previous calls.
func ContextWithLabeler(parent context.Context, l *Labeler) context.Context {
	return context.WithValue(parent, labelerContextKey{}, l)
}

// LabelerFromContext retrieves a Labeler instance from the provided context if
// one is available. If no Labeler was found in the provided context a new, empty
// Labeler is returned and the second return value is false. In this case it is
// safe to use the Labeler but any attributes added to it will not be used.
func LabelerFromContext(ctx context.Context) (*Labeler, bool) {
	l, ok := ctx.Value(labelerContextKey{}).(*Labeler)
	if !ok {
		l = &Labeler{}
	}
	return l, ok
}

// appendAttributes appends the Labeler's attributes to attrs.
func (l *Labeler) appendAttributes(attrs []attribute.KeyValue) []attribute.KeyValue {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append(attrs, l.attributes...)
}
