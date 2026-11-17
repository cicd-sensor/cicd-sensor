// Copyright 2022-2025 The Connect Authors
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

package otelconnect

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

const statusCodeOK = "OK" // success

// AttributeFilter is used to filter attributes out based on the [connect.Spec]
// and [attribute.KeyValue]. If the filter returns true the attribute will be
// kept else it will be removed. AttributeFilter must be safe to call concurrently.
type AttributeFilter func(connect.Spec, attribute.KeyValue) bool

func (filter AttributeFilter) filter(spec connect.Spec, values ...attribute.KeyValue) []attribute.KeyValue {
	if filter == nil {
		return values
	}
	// Assign a new slice of zero length with the same underlying
	// array as the values slice. This avoids unnecessary memory allocations.
	filteredValues := values[:0]
	for _, attr := range values {
		if filter(spec, attr) {
			filteredValues = append(filteredValues, attr)
		}
	}
	clear(values[len(filteredValues):])
	return filteredValues
}

// filterFrom filters values from start onward, in place.
func (filter AttributeFilter) filterFrom(spec connect.Spec, values []attribute.KeyValue, start int) []attribute.KeyValue {
	return values[:start+len(filter.filter(spec, values[start:]...))]
}

func addRequestAttributes(protocol string, attrs []attribute.KeyValue, spec connect.Spec) []attribute.KeyValue {
	return append(attrs,
		semconv.RPCSystemNameKey.String(protocol),
		semconv.RPCMethodKey.String(strings.TrimLeft(spec.Procedure, "/")),
	)
}

func addAddressAttributes(attrs []attribute.KeyValue, address string, addressKey, portKey attribute.Key) []attribute.KeyValue {
	if address == "" {
		return attrs
	}
	if host, port, err := net.SplitHostPort(address); err == nil {
		if portInt, err := strconv.Atoi(port); err == nil {
			return append(attrs, addressKey.String(host), portKey.Int(portInt))
		}
	}
	return append(attrs, addressKey.String(address))
}

func addStatusAttributes(attrs []attribute.KeyValue, err error) []attribute.KeyValue {
	switch {
	case err == nil:
		return append(attrs, semconv.RPCResponseStatusCodeKey.String(statusCodeOK))
	case connecthttp.IsNotModifiedError(err):
		// A "not modified" error is special: it's code is technically "unknown" but
		// it would be misleading to label it as an unknown error since it's not really
		// an error, but rather a sentinel to trigger a "304 Not Modified" HTTP status.
		return append(attrs,
			semconv.RPCResponseStatusCodeKey.String(statusCodeOK),
			semconv.HTTPResponseStatusCodeKey.Int(http.StatusNotModified),
		)
	default:
		// Mirror gRPC's canonical names, e.g. DEADLINE_EXCEEDED.
		code := strings.ToUpper(connect.CodeOf(err).String())
		return append(attrs,
			semconv.RPCResponseStatusCodeKey.String(code),
			semconv.ErrorTypeKey.String(code),
		)
	}
}

func headerAttributes(eventType string, metadata *connect.Header, allowedKeys []string) []attribute.KeyValue {
	attributes := make([]attribute.KeyValue, 0, len(allowedKeys))
	return addHeaderAttributes(attributes, eventType, metadata, allowedKeys)
}

func addHeaderAttributes(attributes []attribute.KeyValue, eventType string, metadata *connect.Header, allowedKeys []string) []attribute.KeyValue {
	for _, allowedKey := range allowedKeys {
		values := metadata.Values(allowedKey)
		if len(values) == 0 {
			continue
		}
		key := strings.ToLower(allowedKey)
		if eventType == requestKey {
			attributes = append(attributes, semconv.RPCRequestMetadata(key, values...))
		} else {
			attributes = append(attributes, semconv.RPCResponseMetadata(key, values...))
		}
	}
	return attributes
}
