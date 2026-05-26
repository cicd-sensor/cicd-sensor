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
	"pluginrpc.com/pluginrpc"
)

// Main is the main entrypoint for a plugin that implements the given Spec.
//
// A plugin just needs to provide a Spec, and then call this function within main.
//
//	func main() {
//		check.Main(
//			&check.Spec {
//				Rules: []*check.RuleSpec{
//					{
//						ID:      "TIMESTAMP_SUFFIX",
//						Default: true,
//						Purpose: "Checks that all google.protobuf.Timestamps end in _time.",
//						Type:    check.RuleTypeLint,
//						Handler: check.RuleHandlerFunc(handleTimestampSuffix),
//					},
//				},
//			},
//		)
//	}
func Main(spec *Spec, options ...MainOption) {
	mainOptions := newMainOptions()
	for _, option := range options {
		option(mainOptions)
	}
	pluginrpc.Main(
		func() (pluginrpc.Server, error) {
			return NewServer(
				spec,
				ServerWithParallelism(mainOptions.parallelism),
			)
		},
	)
}

// MainOption is an option for Main.
type MainOption func(*mainOptions)

// MainWithParallelism returns a new MainOption that sets the parallelism by which Rules
// will be run.
//
// If this is set to a value >= 1, this many concurrent Rules can be run at the same time.
// A value of 0 indicates the default behavior, which is to use runtime.GOMAXPROCS(0).
//
// A value if < 0 has no effect.
func MainWithParallelism(parallelism int) MainOption {
	return func(mainOptions *mainOptions) {
		if parallelism < 0 {
			parallelism = 0
		}
		mainOptions.parallelism = parallelism
	}
}

// *** PRIVATE ***

type mainOptions struct {
	parallelism int
}

func newMainOptions() *mainOptions {
	return &mainOptions{}
}
