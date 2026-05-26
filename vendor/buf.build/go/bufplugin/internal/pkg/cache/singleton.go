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

package cache

import (
	"context"
	"errors"
	"sync"
)

// Singleton is a singleton.
//
// It must be constructed with NewSingleton.
type Singleton[V any] struct {
	get   func(context.Context) (V, error)
	value V
	err   error
	// Storing a bool to not deal with generic zero/nil comparisons.
	called bool
	lock   sync.RWMutex
}

// NewSingleton returns a new Singleton.
//
// The get function must only return the zero value of V on error.
func NewSingleton[V any](get func(context.Context) (V, error)) *Singleton[V] {
	return &Singleton[V]{
		get: get,
	}
}

// Get gets the value, or returns the error in loading the value.
//
// The given context will be used to load the value if not already loaded.
//
// If Singletons call Singletons, lock ordering must be respected.
func (s *Singleton[V]) Get(ctx context.Context) (V, error) {
	if s.get == nil {
		var zero V
		return zero, errors.New("must create singleton with NewSingleton and a non-nil get function")
	}
	s.lock.RLock()
	if s.called {
		s.lock.RUnlock()
		return s.value, s.err
	}
	s.lock.RUnlock()
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.called {
		s.value, s.err = s.get(ctx)
		s.called = true
	}
	return s.value, s.err
}
