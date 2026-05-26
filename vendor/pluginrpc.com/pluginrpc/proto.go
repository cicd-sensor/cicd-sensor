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

	"google.golang.org/protobuf/proto"
)

// toProtoMessage casts the value into a proto.Message, returning an error
// if value is not a proto.Message.
//
// We use anys in our code instead of proto.Message for forwards-compatibility; right
// now, we expect jsonpb-encoded values over the wire, but we could easily extend pluginrpc
// to allow for different codecs, and we could add a Codec interface to this library. Since
// everything needs to be a proto.Message right now, this isn't a problem.
func toProtoMessage(value any) (proto.Message, error) {
	if value == nil {
		return nil, nil
	}
	message, ok := value.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("expected proto.Message, got %T", value)
	}
	return message, nil
}
