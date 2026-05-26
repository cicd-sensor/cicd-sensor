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
	"context"
	"net/http"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

var (
	// ConnectRPCSystem indicates that the semantic conventions for
	// ConnectRPC should be used.
	ConnectRPCSystem = connectRPCSystem{} //nolint:gochecknoglobals
	// GRPCSystem indicates that the semantic conventions for gRPC
	// should be used.
	GRPCSystem = gRPCSystem{} //nolint:gochecknoglobals
)

// An Option configures the OpenTelemetry instrumentation.
type Option interface {
	apply(*config)
}

// WithPropagator configures the instrumentation to use the supplied propagator
// when extracting and injecting trace context. By default, the instrumentation
// uses [otel.GetTextMapPropagator].
func WithPropagator(propagator propagation.TextMapPropagator) Option {
	return &propagatorOption{propagator}
}

// WithMeterProvider configures the instrumentation to use the supplied [metric.MeterProvider]
// when extracting and injecting trace context. By default, the instrumentation
// uses [otel.GetMeterProvider].
func WithMeterProvider(provider metric.MeterProvider) Option {
	return &meterProviderOption{provider: provider}
}

// WithTracerProvider configures the instrumentation to use the supplied
// provider when creating a tracer. By default, the instrumentation
// uses [otel.GetTracerProvider].
func WithTracerProvider(provider trace.TracerProvider) Option {
	return &tracerProviderOption{provider}
}

// WithFilter configures the instrumentation to emit traces and metrics only
// when the filter function returns true. Filter functions must be safe to call concurrently.
func WithFilter(filter func(context.Context, connect.Spec) bool) Option {
	return &filterOption{filter}
}

// WithoutTracing disables tracing.
func WithoutTracing() Option {
	return WithTracerProvider(tracenoop.NewTracerProvider())
}

// WithoutMetrics disables metrics.
func WithoutMetrics() Option {
	return WithMeterProvider(metricnoop.NewMeterProvider())
}

// WithAttributeFilter sets the attribute filter for all metrics and trace attributes.
func WithAttributeFilter(filter AttributeFilter) Option {
	return &attributeFilterOption{filterAttribute: filter}
}

// WithoutServerPeerAttributes removes net.peer.port and net.peer.name
// attributes from server trace and span attributes. The default behavior
// follows the OpenTelemetry semantic conventions for RPC, but produces very
// high-cardinality data; this option significantly reduces cardinality in most
// environments.
func WithoutServerPeerAttributes() Option {
	return WithAttributeFilter(func(spec connect.Spec, value attribute.KeyValue) bool {
		if spec.IsClient {
			return true
		}
		if value.Key == semconv.NetPeerPortKey {
			return false
		}
		if value.Key == semconv.NetPeerNameKey {
			return false
		}
		return true
	})
}

// WithTrustRemote sets the Interceptor to trust remote spans.
// By default, all incoming server spans are untrusted and will be linked
// with a [trace.Link] and will not be a child span.
// By default, all client spans are trusted and no change occurs when WithTrustRemote is used.
func WithTrustRemote() Option {
	return &trustRemoteOption{}
}

// WithTraceRequestHeader enables header attributes for the request header keys provided.
// Attributes will be added as Trace attributes only.
func WithTraceRequestHeader(keys ...string) Option {
	return &traceRequestHeaderOption{
		keys: keys,
	}
}

// WithTraceResponseHeader enables header attributes for the response header keys provided.
// Attributes will be added as Trace attributes only.
func WithTraceResponseHeader(keys ...string) Option {
	return &traceResponseHeaderOption{
		keys: keys,
	}
}

// WithoutTraceEvents disables trace events for both unary and streaming
// interceptors. This reduces the quantity of data sent to your tracing system
// by omitting per-message information like message size.
func WithoutTraceEvents() Option {
	return &omitTraceEventsOption{}
}

// WithPropagateResponseHeader enables injecting the traceparent header
// into response headers for server-side interceptors. This allows clients
// to correlate their requests with server-side traces.
func WithPropagateResponseHeader() Option {
	return &propagateResponseHeaderOption{}
}

// WithRPCSystem forces the use of the semantic conventions for the given
// RPC system. By default, the conventions used vary based on the actual
// protocol of a request: so requests that a client sends or a server
// receives that use the gRPC or gRPC-Web protocols use the gRPC semantic
// conventions; requests that use ConnectRPC use the ConnectRPC semantic
// conventions.
//
// In a system where a server handles requests for the same service but
// from clients that use multiple protocols, this causes the telemetry
// data to be partitioned by the RPC system conventions. But it is often
// desirable to instead emit uniform telemetry, to allow optics and
// aggregation across RPC systems.
//
// So this option can be used to force uniform metrics and spans, using
// the given RPC system conventions, regardless of the actual protocol.
func WithRPCSystem(system RPCSystem) Option {
	return &rpcSystemOption{system: system}
}

// RPCSystem represents an RPC system, like ConnectRPC or gRPC. Different
// systems have different semantic conventions for how metrics and spans are
// defined.
//
//	https://opentelemetry.io/docs/specs/semconv/rpc/
//
// Valid values currently are ConnectRPCSystem and GRPCSystem.
type RPCSystem interface {
	protocol() string
}

type attributeFilterOption struct {
	filterAttribute AttributeFilter
}

func (o *attributeFilterOption) apply(c *config) {
	if o.filterAttribute != nil {
		c.filterAttribute = o.filterAttribute
	}
}

type propagatorOption struct {
	propagator propagation.TextMapPropagator
}

func (o *propagatorOption) apply(c *config) {
	if o.propagator != nil {
		c.propagator = o.propagator
	}
}

type tracerProviderOption struct {
	provider trace.TracerProvider
}

func (o *tracerProviderOption) apply(c *config) {
	if o.provider != nil {
		c.tracer = o.provider.Tracer(
			instrumentationName,
			trace.WithInstrumentationVersion(semanticVersion),
		)
	}
}

type filterOption struct {
	filter func(context.Context, connect.Spec) bool
}

func (o *filterOption) apply(c *config) {
	if o.filter != nil {
		c.filter = o.filter
	}
}

type meterProviderOption struct {
	provider metric.MeterProvider
}

func (m meterProviderOption) apply(c *config) {
	c.meter = m.provider.Meter(
		instrumentationName,
		metric.WithInstrumentationVersion(semanticVersion),
	)
}

type trustRemoteOption struct{}

func (o *trustRemoteOption) apply(c *config) {
	c.trustRemote = true
}

type traceRequestHeaderOption struct {
	keys []string
}

func (o *traceRequestHeaderOption) apply(c *config) {
	for _, key := range o.keys {
		c.requestHeaderKeys = append(c.requestHeaderKeys, http.CanonicalHeaderKey(key))
	}
}

type traceResponseHeaderOption struct {
	keys []string
}

func (o *traceResponseHeaderOption) apply(c *config) {
	for _, key := range o.keys {
		c.responseHeaderKeys = append(c.responseHeaderKeys, http.CanonicalHeaderKey(key))
	}
}

type omitTraceEventsOption struct{}

func (o *omitTraceEventsOption) apply(c *config) {
	c.omitTraceEvents = true
}

type propagateResponseHeaderOption struct{}

func (o *propagateResponseHeaderOption) apply(c *config) {
	c.propagateResponseHeader = true
}

type rpcSystemOption struct {
	system RPCSystem
}

func (o *rpcSystemOption) apply(c *config) {
	c.rpcSystem = o.system
}

type connectRPCSystem struct{}

func (connectRPCSystem) protocol() string { return connectProtocol }

type gRPCSystem struct{}

func (gRPCSystem) protocol() string { return grpcProtocol }
