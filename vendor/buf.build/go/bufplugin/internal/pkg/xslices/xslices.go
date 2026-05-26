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

package xslices

import (
	"cmp"
	"slices"
)

// Filter filters the slice to only the values where f returns true.
func Filter[T any](s []T, f func(T) bool) []T {
	sf := make([]T, 0, len(s))
	for _, e := range s {
		if f(e) {
			sf = append(sf, e)
		}
	}
	return sf
}

// FilterError filters the slice to only the values where f returns true.
//
// Returns error the first time f returns error.
func FilterError[T any](s []T, f func(T) (bool, error)) ([]T, error) {
	sf := make([]T, 0, len(s))
	for _, e := range s {
		ok, err := f(e)
		if err != nil {
			return nil, err
		}
		if ok {
			sf = append(sf, e)
		}
	}
	return sf, nil
}

// Map maps the slice.
func Map[T1, T2 any](s []T1, f func(T1) T2) []T2 {
	if s == nil {
		return nil
	}
	sm := make([]T2, len(s))
	for i, e := range s {
		sm[i] = f(e)
	}
	return sm
}

// MapError maps the slice.
//
// Returns error the first time f returns error.
func MapError[T1, T2 any](s []T1, f func(T1) (T2, error)) ([]T2, error) {
	if s == nil {
		return nil, nil
	}
	sm := make([]T2, len(s))
	for i, e := range s {
		em, err := f(e)
		if err != nil {
			return nil, err
		}
		sm[i] = em
	}
	return sm, nil
}

// MapKeysToSortedSlice converts the map's keys to a sorted slice.
func MapKeysToSortedSlice[M ~map[K]V, K cmp.Ordered, V any](m M) []K {
	s := MapKeysToSlice(m)
	slices.Sort(s)
	return s
}

// MapKeysToSlice converts the map's keys to a slice.
func MapKeysToSlice[K comparable, V any](m map[K]V) []K {
	s := make([]K, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}

// ToStructMap converts the slice to a map with struct{} values.
func ToStructMap[T comparable](s []T) map[T]struct{} {
	m := make(map[T]struct{}, len(s))
	for _, e := range s {
		m[e] = struct{}{}
	}
	return m
}
