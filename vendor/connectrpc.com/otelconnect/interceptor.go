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
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// Span start options shared by every RPC. clientSpanOptions is a slice, to
// avoid allocating one per RPC.
//
//nolint:gochecknoglobals
var (
	serverSpanKind    = trace.WithSpanKind(trace.SpanKindServer)
	newRootSpan       = trace.WithNewRoot()
	clientSpanOptions = []trace.SpanStartOption{trace.WithSpanKind(trace.SpanKindClient)}
)

// interceptor bundles the configuration and OpenTelemetry instruments for
// one side of an RPC.
type interceptor struct {
	config      config
	instruments instruments
}

// NewServerInterceptor returns a [connect.ServerInterceptor] that adds
// OpenTelemetry metrics and tracing to connect handlers. The interceptor uses
// the OTel global tracer and meter providers by default.
func NewServerInterceptor(options ...Option) (connect.ServerInterceptor, error) {
	intercept, err := newInterceptor(serverKey, options...)
	if err != nil {
		return nil, err
	}
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			return intercept.serveServer(ctx, spec, stream, next)
		}
	}, nil
}

// NewClientInterceptor returns a [connect.ClientInterceptor] that adds
// OpenTelemetry metrics and tracing to connect clients. The interceptor uses
// the OTel global tracer and meter providers by default.
func NewClientInterceptor(options ...Option) (connect.ClientInterceptor, error) {
	intercept, err := newInterceptor(clientKey, options...)
	if err != nil {
		return nil, err
	}
	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			return intercept.serveClient(ctx, spec, next)
		}
	}, nil
}

// newInterceptor applies options and builds the instruments for the named
// side (serverKey or clientKey).
func newInterceptor(side string, options ...Option) (*interceptor, error) {
	cfg := config{
		now: time.Now,
		tracer: otel.GetTracerProvider().Tracer(
			instrumentationName,
			trace.WithInstrumentationVersion(semanticVersion),
		),
		propagator: otel.GetTextMapPropagator(),
		meter: otel.GetMeterProvider().Meter(
			instrumentationName,
			metric.WithInstrumentationVersion(semanticVersion)),
	}
	for _, opt := range options {
		opt.apply(&cfg)
	}
	sideInstruments, err := createInstruments(cfg.meter, side, cfg.durationHistogramOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s instruments: %w", side, err)
	}
	return &interceptor{
		config:      cfg,
		instruments: sideInstruments,
	}, nil
}

// serverCall holds the state of one handler call.
type serverCall struct {
	rpcCall

	spanAttributes [4]attribute.KeyValue // RPC and peer attributes
	traceOpts      [5]trace.SpanStartOption
}

// serveServer implements otel tracing and metrics for connect handlers.
// Unary and streaming RPCs both flow through this method. The handler's
// error is the outcome of the RPC, so the stream is not wrapped.
func (i *interceptor) serveServer(ctx context.Context, spec connect.Spec, stream connect.ServerStream, next connect.ServerFunc) error {
	requestStartTime := i.config.now()
	if i.config.filter != nil {
		if !i.config.filter(ctx, spec) {
			return next(ctx, spec, stream)
		}
	}
	callInfo, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		callInfo = &connect.CallInfo{}
	}
	call := &serverCall{rpcCall: rpcCall{
		config:   &i.config,
		duration: i.instruments.duration,
		spec:     spec,
		callInfo: callInfo,
		start:    requestStartTime,
	}}
	ctx = call.withLabeler(ctx)
	name := strings.TrimLeft(spec.Procedure, "/")
	protocol := protocolToSemConv(callInfo.Protocol, i.config.rpcSystem)
	attributes := i.config.filterAttribute.filter(spec, addRequestAttributes(protocol, call.attributes[:0], spec)...)
	spanAttributes := append(call.spanAttributes[:0], attributes...)
	if i.config.serverPeerAttributes {
		spanAttributes = i.config.filterAttribute.filterFrom(spec,
			addAddressAttributes(spanAttributes, callInfo.PeerAddr, semconv.NetworkPeerAddressKey, semconv.NetworkPeerPortKey),
			len(spanAttributes),
		)
	}
	// extract any request headers into the context
	carrier := metadataCarrier{m: callInfo.RequestHeader()}
	traceOpts := append(call.traceOpts[:0],
		serverSpanKind,
		trace.WithAttributes(spanAttributes...),
	)
	if len(i.config.requestHeaderKeys) > 0 {
		traceOpts = append(traceOpts,
			trace.WithAttributes(headerAttributes(requestKey, callInfo.RequestHeader(), i.config.requestHeaderKeys)...),
		)
	}
	if !trace.SpanContextFromContext(ctx).IsValid() {
		ctx = i.config.propagator.Extract(ctx, carrier)
		// Without a remote parent the span is already a new root.
		if link := trace.LinkFromContext(ctx); !i.config.trustRemote && link.SpanContext.IsValid() {
			traceOpts = append(traceOpts,
				newRootSpan,
				trace.WithLinks(link),
			)
		}
	}
	// start a new span with any trace that is in the context
	ctx, call.span = i.config.tracer.Start( //nolint:spancheck // ended by defer
		ctx,
		name,
		traceOpts...,
	)
	defer call.span.End()

	// Inject traceparent into response headers if enabled
	if i.config.propagateResponseHeader {
		responseCarrier := metadataCarrier{m: callInfo.ResponseHeader()}
		i.config.propagator.Inject(ctx, responseCarrier)
	}

	err := next(ctx, spec, stream)
	call.span.SetStatus(serverSpanStatus(err))
	// The span already has the RPC attributes.
	call.record(ctx, attributes, len(attributes), err)
	return err
}

// serveClient implements otel tracing and metrics for connect clients.
// Unary and streaming RPCs both flow through this method. The returned
// stream ends the span when the RPC completes.
func (i *interceptor) serveClient(ctx context.Context, spec connect.Spec, next connect.ClientFunc) (connect.ClientStream, error) {
	if i.config.filter != nil {
		if !i.config.filter(ctx, spec) {
			return next(ctx, spec)
		}
	}
	call := &clientCall{rpcCall: rpcCall{
		config:   &i.config,
		duration: i.instruments.duration,
		spec:     spec,
		start:    i.config.now(),
	}}
	ctx = call.withLabeler(ctx)
	name := strings.TrimLeft(spec.Procedure, "/")
	callInfo, ok := connect.CallInfoForClientContext(ctx)
	if !ok {
		ctx, callInfo = connect.NewClientContext(ctx)
	}
	call.callInfo = callInfo
	// Span is closed on context cancelation or when the stream is closed.
	ctx, call.span = i.config.tracer.Start( //nolint:spancheck // ended by call.end
		ctx,
		name,
		clientSpanOptions...,
	)
	call.ctx = ctx
	// inject the newly created span into the carrier
	carrier := metadataCarrier{m: callInfo.RequestHeader()}
	i.config.propagator.Inject(ctx, carrier)
	conn, err := next(ctx, spec)
	if err != nil {
		// The transport failed to open the stream. Record and finalize now.
		call.setError(err)
		call.end()
		return nil, err
	}
	call.ClientStream = conn
	// Watch the context only if it can abandon the stream. Client.CallUnary
	// always closes unary streams.
	if spec.StreamType != connect.StreamTypeUnary && ctx.Done() != nil {
		call.stop = context.AfterFunc(ctx, call.cancel)
	}
	return call, nil
}

// clientCall holds the state of one client call. It wraps the stream and
// ends the RPC on the first Receive error, Close, or context cancellation.
type clientCall struct {
	connect.ClientStream
	rpcCall

	ctx  context.Context //nolint:containedctx // used by end
	stop func() bool     // stops watching ctx, or nil
	once sync.Once
	mu   sync.Mutex
	err  error // last Send or Receive error, excluding io.EOF
}

func (c *clientCall) Send(msg any) error {
	err := c.ClientStream.Send(msg)
	c.setError(err)
	return err
}

func (c *clientCall) Receive(msg any) error {
	err := c.ClientStream.Receive(msg)
	if err != nil {
		c.setError(err)
		c.finish()
	}
	return err
}

func (c *clientCall) Close() error {
	err := c.ClientStream.Close()
	c.finish()
	return err
}

func (c *clientCall) setError(err error) {
	if err == nil || errors.Is(err, io.EOF) {
		return
	}
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

func (c *clientCall) finish() {
	if c.stop != nil {
		c.stop()
	}
	c.once.Do(c.end)
}

// cancel ends the RPC when its context is done.
func (c *clientCall) cancel() {
	c.once.Do(c.end)
}

// end records the outcome of the RPC and ends its span. It runs once.
func (c *clientCall) end() {
	c.mu.Lock()
	err := c.err
	c.mu.Unlock()
	// The protocol and peer are known once the stream is open.
	protocol := protocolToSemConv(c.callInfo.Protocol, c.config.rpcSystem)
	attributes := addRequestAttributes(protocol, c.attributes[:0], c.spec)
	attributes = addAddressAttributes(attributes, c.callInfo.PeerAddr, semconv.ServerAddressKey, semconv.ServerPortKey)
	attributes = c.config.filterAttribute.filter(c.spec, attributes...)
	if c.span.IsRecording() {
		c.span.SetAttributes(headerAttributes(requestKey, c.callInfo.RequestHeader(), c.config.requestHeaderKeys)...)
	}
	c.span.SetStatus(clientSpanStatus(err))
	c.record(c.ctx, attributes, 0, err)
	c.span.End()
}

// rpcCall holds the per-RPC state shared by both sides. Each side embeds it,
// so an RPC allocates its state once.
type rpcCall struct {
	config   *config
	duration metric.Float64Histogram
	spec     connect.Spec
	callInfo *connect.CallInfo
	span     trace.Span
	start    time.Time
	labeler  *Labeler // the context's Labeler, or ownLabeler
	// Storage, to avoid separate allocations.
	ownLabeler    Labeler
	attributes    [6]attribute.KeyValue // up to 4 RPC and 2 status attributes
	recordOptions [1]metric.RecordOption
}

// withLabeler returns ctx with the RPC's [Labeler].
func (c *rpcCall) withLabeler(ctx context.Context) context.Context {
	if labeler, ok := ctx.Value(labelerContextKey{}).(*Labeler); ok {
		c.labeler = labeler
		return ctx
	}
	c.labeler = &c.ownLabeler
	return ContextWithLabeler(ctx, c.labeler)
}

// record records the outcome of the RPC on its span and duration metric.
// The span already has the first spanFrom attributes. The attributes need
// spare capacity for the status attributes. It does not end the span.
func (c *rpcCall) record(ctx context.Context, attributes []attribute.KeyValue, spanFrom int, err error) {
	attributes = c.config.filterAttribute.filterFrom(c.spec, addStatusAttributes(attributes, err), len(attributes))
	if c.span.IsRecording() {
		// Set once, as the SDK grows the span's attributes on every call.
		c.span.SetAttributes(attributes[spanFrom:]...)
		c.span.SetAttributes(headerAttributes(responseKey, c.callInfo.ResponseHeader(), c.config.responseHeaderKeys)...)
	}
	// NewSet sorts attributes in place, so call it after SetAttributes.
	attributes = c.labeler.appendAttributes(attributes)
	c.recordOptions[0] = metric.WithAttributeSet(attribute.NewSet(attributes...))
	duration := c.config.now().Sub(c.start).Seconds()
	c.duration.Record(ctx, duration, c.recordOptions[:]...)
}

// protocolToSemConv converts the protocol string to the OpenTelemetry format.
func protocolToSemConv(protocol string, system RPCSystem) string {
	if system != nil {
		// If an explicit system was configured, that overrides the wire protocol.
		return system.protocol()
	}
	switch protocol {
	case connect.ProtocolNameGRPCWeb, connect.ProtocolNameGRPC:
		return grpcProtocol
	case connect.ProtocolNameConnect:
		return connectProtocol
	default:
		return protocol
	}
}

func clientSpanStatus(err error) (codes.Code, string) {
	if err == nil {
		return codes.Unset, ""
	}
	if connecthttp.IsNotModifiedError(err) {
		return codes.Unset, ""
	}
	if connectErr := new(connect.Error); errors.As(err, &connectErr) {
		return codes.Error, connectErr.Message()
	}
	return codes.Error, err.Error()
}

func serverSpanStatus(err error) (codes.Code, string) {
	if err == nil {
		return codes.Unset, ""
	}
	if connecthttp.IsNotModifiedError(err) {
		return codes.Unset, ""
	}

	if connectErr := new(connect.Error); errors.As(err, &connectErr) {
		switch connectErr.Code() {
		case connect.CodeUnknown,
			connect.CodeDeadlineExceeded,
			connect.CodeUnimplemented,
			connect.CodeInternal,
			connect.CodeUnavailable,
			connect.CodeDataLoss:
			return codes.Error, connectErr.Message()
		case connect.CodeCanceled,
			connect.CodeInvalidArgument,
			connect.CodeNotFound,
			connect.CodeAlreadyExists,
			connect.CodePermissionDenied,
			connect.CodeResourceExhausted,
			connect.CodeFailedPrecondition,
			connect.CodeAborted,
			connect.CodeOutOfRange,
			connect.CodeUnauthenticated:
			return codes.Unset, ""
		default:
			return codes.Unset, ""
		}
	}

	return codes.Error, err.Error()
}

// metadataCarrier adapts a [*connect.Header] to OpenTelemetry's
// [propagation.TextMapCarrier] for trace-context propagation.
type metadataCarrier struct {
	m *connect.Header
}

func (c metadataCarrier) Get(key string) string {
	return c.m.Get(key)
}

func (c metadataCarrier) Set(key, value string) { c.m.Set(key, value) }

func (c metadataCarrier) Keys() []string {
	keys := make([]string, 0, c.m.Len())
	for key := range c.m.All() {
		keys = append(keys, key)
	}
	return keys
}
