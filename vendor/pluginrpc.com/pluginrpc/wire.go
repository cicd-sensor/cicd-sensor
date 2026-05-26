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
	pluginrpcv1 "buf.build/gen/go/pluginrpc/pluginrpc/protocolbuffers/go/pluginrpc/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func marshalRequest(format Format, requestValue any) ([]byte, error) {
	if requestValue == nil {
		return nil, nil
	}
	protoRequestValue, err := toProtoMessage(requestValue)
	if err != nil {
		return nil, err
	}
	anyRequestValue, err := anypb.New(protoRequestValue)
	if err != nil {
		return nil, err
	}
	protoRequest := &pluginrpcv1.Request{
		Value: anyRequestValue,
	}
	codec, err := codecForFormat(format)
	if err != nil {
		return nil, err
	}
	return codec.Marshal(protoRequest)
}

func unmarshalRequest(format Format, data []byte, requestValue any) error {
	if len(data) == 0 {
		return nil
	}
	codec, err := codecForFormat(format)
	if err != nil {
		return err
	}
	protoRequest := &pluginrpcv1.Request{}
	if err := codec.Unmarshal(data, protoRequest); err != nil {
		return err
	}
	anyRequestValue := protoRequest.GetValue()
	if anyRequestValue == nil {
		return nil
	}
	protoRequestValue, err := toProtoMessage(requestValue)
	if err != nil {
		return err
	}
	return anypb.UnmarshalTo(anyRequestValue, protoRequestValue, proto.UnmarshalOptions{})
}

func marshalResponse(format Format, responseValue any, err error) ([]byte, error) {
	var anyResponseValue *anypb.Any
	if responseValue != nil {
		protoResponseValue, err := toProtoMessage(responseValue)
		if err != nil {
			return nil, err
		}
		anyResponseValue, err = anypb.New(protoResponseValue)
		if err != nil {
			return nil, err
		}
	}
	protoResponse := &pluginrpcv1.Response{
		Value: anyResponseValue,
		Error: WrapError(err).ToProto(),
	}
	codec, err := codecForFormat(format)
	if err != nil {
		return nil, err
	}
	return codec.Marshal(protoResponse)
}

func unmarshalResponse(format Format, data []byte, responseValue any) error {
	if len(data) == 0 {
		return nil
	}
	codec, err := codecForFormat(format)
	if err != nil {
		return err
	}
	protoResponse := &pluginrpcv1.Response{}
	if err := codec.Unmarshal(data, protoResponse); err != nil {
		return err
	}
	if anyResponseValue := protoResponse.GetValue(); anyResponseValue != nil {
		protoResponseValue, err := toProtoMessage(responseValue)
		if err != nil {
			return err
		}
		if err := anypb.UnmarshalTo(anyResponseValue, protoResponseValue, proto.UnmarshalOptions{}); err != nil {
			return err
		}
	}
	if protoError := protoResponse.GetError(); protoError != nil {
		return NewErrorForProto(protoError)
	}
	return nil
}
