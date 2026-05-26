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
	"strconv"

	checkv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/check/v1"
)

const (
	// RuleTypeLint is a lint Rule.
	RuleTypeLint RuleType = 1
	// RuleTypeBreaking is a breaking change Rule.
	RuleTypeBreaking RuleType = 2
)

var (
	ruleTypeToString = map[RuleType]string{
		RuleTypeLint:     "lint",
		RuleTypeBreaking: "breaking",
	}
	ruleTypeToProtoRuleType = map[RuleType]checkv1.RuleType{
		RuleTypeLint:     checkv1.RuleType_RULE_TYPE_LINT,
		RuleTypeBreaking: checkv1.RuleType_RULE_TYPE_BREAKING,
	}
	protoRuleTypeToRuleType = map[checkv1.RuleType]RuleType{
		checkv1.RuleType_RULE_TYPE_LINT:     RuleTypeLint,
		checkv1.RuleType_RULE_TYPE_BREAKING: RuleTypeBreaking,
	}
)

// RuleType is the type of Rule.
type RuleType int

// String implements fmt.Stringer.
func (t RuleType) String() string {
	if s, ok := ruleTypeToString[t]; ok {
		return s
	}
	return strconv.Itoa(int(t))
}
