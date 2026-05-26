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

import "io"

// Env represents an environment.
//
// This wraps items like args, environment variables, and stdio.
//
// When calling Main, this uses the values from the os package: os.Args[1:], os.Environ,
// os.Stdin, os.Stdout, and os.Stderr.
type Env struct {
	// Args are the program arguments.
	//
	// Does not include the program name.
	Args []string
	// Environment are the environment variables.
	Environ []string
	// Stdin is the stdin for the plugin.
	Stdin io.Reader
	// Stdout is the stdout for the plugin.
	Stdout io.Writer
	// Stderr is the stderr for the plugin.
	Stderr io.Writer
}

// PluginEnv represents an environment that a plugin is run within.
//
// This provides the environment variables and stderr. A plugin implementation should not have
// access to stdin, stdout, or the args, as these are controlled by the plugin framework.
//
// When calling Main, this uses the values os.Environ and os.Stderr.
type PluginEnv struct {
	// Environment are the environment variables.
	Environ []string
	// Stderr is the stderr for the plugin.
	Stderr io.Writer
}
