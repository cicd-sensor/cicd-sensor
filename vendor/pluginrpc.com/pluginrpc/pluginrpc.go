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

// Package pluginrpc implements an RPC framework for plugins.
package pluginrpc // import "pluginrpc.com/pluginrpc"

const (
	// Version is the semantic version of the pluginrpc module.
	Version = "0.5.0"

	// IsAtLeastVersion0_1_0 is used in compile-time handshake's with pluginrpc's generated code.
	IsAtLeastVersion0_1_0 = true
	// IsAtLeastVersion0_4_0 is used in compile-time handshake's with pluginrpc's generated code.
	IsAtLeastVersion0_4_0 = true
)
