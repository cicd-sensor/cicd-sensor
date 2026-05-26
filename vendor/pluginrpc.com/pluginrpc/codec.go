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

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	binaryCodec = &codec{
		Marshal:   proto.Marshal,
		Unmarshal: proto.Unmarshal,
	}
	jsonCodec = &codec{
		Marshal:   protojson.MarshalOptions{UseProtoNames: true}.Marshal,
		Unmarshal: protojson.Unmarshal,
	}

	formatToCodec = map[Format]*codec{
		FormatBinary: binaryCodec,
		FormatJSON:   jsonCodec,
	}
)

type codec struct {
	Marshal   func(message proto.Message) ([]byte, error)
	Unmarshal func(data []byte, message proto.Message) error
}

func codecForFormat(format Format) (*codec, error) {
	codec, ok := formatToCodec[format]
	if !ok {
		return nil, fmt.Errorf("unknown Format: %v", format)
	}
	return codec, nil
}
