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
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

const (
	// ProtocolFlagName is the name of the protocol bool flag.
	ProtocolFlagName = "protocol"
	// SpecFlagName is the name of the spec bool flag.
	SpecFlagName = "spec"
	// FormatFlagName is the name of the format string flag.
	FormatFlagName = "format"

	protocolVersion = 1
	flagWrapping    = 140
)

type flags struct {
	printProtocol bool
	printSpec     bool
	format        Format
}

func parseFlags(output io.Writer, args []string, spec Spec, doc string) (*flags, []string, error) {
	flags := &flags{}
	var formatString string
	flagSet := pflag.NewFlagSet("plugin", pflag.ContinueOnError)
	flagSet.Usage = func() {
		_, _ = fmt.Fprint(output, getFlagUsage(flagSet, spec, doc))
	}
	flagSet.SetOutput(output)
	flagSet.BoolVar(&flags.printProtocol, ProtocolFlagName, false, "Print the protocol to stdout and exit.")
	flagSet.BoolVar(&flags.printSpec, SpecFlagName, false, "Print the spec to stdout in the specified format and exit.")
	flagSet.StringVar(&formatString, FormatFlagName, formatBinaryString, fmt.Sprintf("The format to use for requests, responses, and specs. Must be one of [%q, %q].", formatBinaryString, formatJSONString))
	if err := flagSet.Parse(args); err != nil {
		return nil, nil, err
	}
	if flags.printProtocol && flags.printSpec {
		return nil, nil, fmt.Errorf("cannot specify both --%s and --%s", ProtocolFlagName, SpecFlagName)
	}
	format := FormatBinary
	if formatString != "" {
		format = FormatForString(formatString)
		if format == 0 {
			return nil, nil, fmt.Errorf("invalid value for --%s: %q", FormatFlagName, formatString)
		}
	}
	if err := validateFormat(format); err != nil {
		return nil, nil, err
	}
	flags.format = format
	return flags, flagSet.Args(), nil
}

func getFlagUsage(flagSet *pflag.FlagSet, spec Spec, doc string) string {
	var sb strings.Builder
	if doc != "" {
		_, _ = sb.WriteString(doc)
		_, _ = sb.WriteString("\n\n")
	}
	_, _ = sb.WriteString("Commands:\n\n")
	var argBasedProcedureStrings []string
	var pathBasedProcedureStrings []string
	for _, procedure := range spec.Procedures() {
		if args := procedure.Args(); len(args) > 0 {
			argBasedProcedureStrings = append(argBasedProcedureStrings, strings.Join(args, " "))
		} else {
			pathBasedProcedureStrings = append(pathBasedProcedureStrings, procedure.Path())
		}
	}
	sort.Strings(argBasedProcedureStrings)
	sort.Strings(pathBasedProcedureStrings)
	for _, procedureString := range append(argBasedProcedureStrings, pathBasedProcedureStrings...) {
		_, _ = sb.WriteString("  ")
		_, _ = sb.WriteString(procedureString)
		_, _ = sb.WriteString("\n")
	}
	_, _ = sb.WriteString("\nFlags:\n\n")
	_, _ = sb.WriteString(flagSet.FlagUsagesWrapped(flagWrapping))
	_, _ = sb.WriteString("  -h, --help            Show this help.\n")
	return sb.String()
}

func marshalProtocol(value int) []byte {
	return []byte(strconv.Itoa(value) + "\n")
}

func unmarshalProtocol(data []byte) (int, error) {
	dataString := strings.TrimSpace(string(data))
	value, err := strconv.Atoi(dataString)
	if err != nil {
		return 0, fmt.Errorf("invalid protocol: %q", dataString)
	}
	return value, err
}

func marshalSpec(format Format, value any) ([]byte, error) {
	protoValue, err := toProtoMessage(value)
	if err != nil {
		return nil, err
	}
	codec, err := codecForFormat(format)
	if err != nil {
		return nil, err
	}
	return codec.Marshal(protoValue)
}

func unmarshalSpec(format Format, data []byte, value any) error {
	if len(data) == 0 {
		return nil
	}
	codec, err := codecForFormat(format)
	if err != nil {
		return err
	}
	protoValue, err := toProtoMessage(value)
	if err != nil {
		return err
	}
	return codec.Unmarshal(data, protoValue)
}
