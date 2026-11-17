otelconnect
===========

[![Build](https://github.com/connectrpc/otelconnect-go/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/connectrpc/otelconnect-go/actions/workflows/ci.yaml)
[![GoDoc](https://pkg.go.dev/badge/connectrpc.com/otelconnect.svg)][godoc]

`connectrpc.com/otelconnect` adds support for [OpenTelemetry][opentelemetry.io]
tracing and metrics collection to [Connect][connect] servers and clients.

For more on Connect, OpenTelemetry, and `otelconnect`, see the [Connect
announcement blog post][blog] and the observability documentation on
[connectrpc.com](https://connectrpc.com/docs/go/observability/).

## An example

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/otelconnect"
	// Generated from your protobuf schema by protoc-gen-go and
	// protoc-gen-connect-go.
	pingv1 "connectrpc.com/otelconnect/internal/gen/observability/ping/v1"
	"connectrpc.com/otelconnect/internal/gen/observability/ping/v1/pingv1connect"
)

func main() {
	otelInterceptor, err := otelconnect.NewServerInterceptor()
	if err != nil {
		log.Fatal(err)
	}

	// otelconnect.NewServerInterceptor provides an interceptor that adds
	// tracing and metrics to handlers; otelconnect.NewClientInterceptor does
	// the same for clients. By default, they use OpenTelemetry's global
	// TracerProvider and MeterProvider, which you can configure by following
	// the OpenTelemetry documentation. If you'd prefer to avoid globals, use
	// otelconnect.WithTracerProvider and otelconnect.WithMeterProvider.
	server := connect.NewServer(otelInterceptor)
	pingv1connect.RegisterPingServiceHandler(server, &pingv1connect.UnimplementedPingServiceHandler{})

	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	http.ListenAndServe("localhost:8080", mux)
}

func makeRequest() {
	otelInterceptor, err := otelconnect.NewClientInterceptor()
	if err != nil {
		log.Fatal(err)
	}

	client := pingv1connect.NewPingServiceClient(
		connect.NewClient(
			connecthttp.NewTransport(http.DefaultClient, "http://localhost:8080"),
			otelInterceptor,
		),
	)
	resp, err := client.Ping(context.Background(), &pingv1.PingRequest{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp)
}

```

## Configuration for internal services

By default, instrumented servers are conservative and behave as though they're
internet-facing. They don't trust any tracing information sent by the client,
and will create new trace spans for each request. The new spans are linked to
the remote span for reference (using OpenTelemetry's
[`trace.Link`](https://pkg.go.dev/go.opentelemetry.io/otel/trace#Link)), but
tracing UIs will display the request as a new top-level transaction.

If your server is deployed as an internal service, configure `otelconnect` to
trust the client's tracing information using
[`otelconnect.WithTrustRemote`][WithTrustRemote]. With this option, servers
will create child spans for each request.

## Semantic conventions

`otelconnect` follows the [OpenTelemetry RPC semantic conventions][otel-rpc-conventions]
(semconv v1.43.0). Spans and metrics carry `rpc.system.name` (`connectrpc` or
`grpc`), the fully-qualified `rpc.method`, `rpc.response.status_code` and, on
failure, `error.type`. Status codes are the uppercase Connect codes
(`NOT_FOUND`, `DEADLINE_EXCEEDED`) for every RPC system, or `OK`. Client
telemetry adds `server.address` and `server.port`; server spans can add
`network.peer.address` and `network.peer.port` (see below).

Each side records one metric, `rpc.{server,client}.call.duration`, in seconds.
[`WithDurationHistogramOptions`][WithDurationHistogramOptions] changes its
buckets, and a [`Labeler`][Labeler] adds attributes to metrics from a handler
or client.

## Reducing tracing cardinality

The [OpenTelemetry RPC conventions][otel-rpc-conventions] tag server spans with
the remote client's address and ephemeral port. These are high-cardinality, so
`otelconnect` omits them by default; opt back in with
[`otelconnect.WithServerPeerAttributes`][WithServerPeerAttributes]. For
more customizable attribute filtering, use
[`otelconnect.WithAttributeFilter`][WithAttributeFilter]; to skip RPCs
entirely, use [`otelconnect.WithFilter`][WithFilter].

Interceptors run inside the Connect handler, so HTTP middleware cannot see
their span. To trace at the HTTP layer too, wrap the mux with
[`otelhttp`](https://pkg.go.dev/go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp);
the interceptor finds its span in the request context and creates the RPC span
as a child. Note that `otelhttp` then decides whether to trust incoming trace
headers, not [`otelconnect.WithTrustRemote`][WithTrustRemote].

## Status

|         | Unary | Streaming Client | Streaming Handler |
|---------|:-----:|:----------------:|:-----------------:|
| Metrics | ✅    | ✅               | ✅                |
| Tracing | ✅    | ✅               | ✅                |

## Ecosystem

* [connect-go][connect]: Service handlers and clients for Go
* [connect-swift]: Swift clients for idiomatic gRPC & Connect RPC
* [connect-kotlin]: Kotlin clients for idiomatic gRPC & Connect RPC
* [connect-es]: Type-safe APIs with Protobuf and TypeScript.
* [Buf Studio]: web UI for ad-hoc RPCs
* [conformance]: Connect, gRPC, and gRPC-Web interoperability tests

## Support and Versioning

`otelconnect` supports:

* The [two most recent major releases][go-support-policy] of Go.
* v1 of the `go.opentelemetry.io/otel` tracing and metrics SDK.
* v2 of `connectrpc.com/connect`.

`otelconnect` v0.10.x is the last release series compatible with
`connectrpc.com/connect` v1. If you're still on connect v1, pin
`connectrpc.com/otelconnect@v0.10`.

## Legal

Offered under the [Apache 2 license][license].

[Buf Studio]: https://buf.build/studio
[Labeler]: https://pkg.go.dev/connectrpc.com/otelconnect#Labeler
[WithAttributeFilter]: https://pkg.go.dev/connectrpc.com/otelconnect#WithAttributeFilter
[WithDurationHistogramOptions]: https://pkg.go.dev/connectrpc.com/otelconnect#WithDurationHistogramOptions
[WithFilter]: https://pkg.go.dev/connectrpc.com/otelconnect#WithFilter
[WithServerPeerAttributes]: https://pkg.go.dev/connectrpc.com/otelconnect#WithServerPeerAttributes
[WithTrustRemote]: https://pkg.go.dev/connectrpc.com/otelconnect#WithTrustRemote
[blog]: https://buf.build/blog/connect-a-better-grpc
[conformance]: https://github.com/connectrpc/conformance
[connect]: https://github.com/connectrpc/connect-go
[connect-kotlin]: https://github.com/connectrpc/connect-kotlin
[connect-swift]: https://github.com/connectrpc/connect-swift
[connect-es]: https://github.com/connectrpc/connect-es
[docs]: https://connectrpc.com
[go-support-policy]: https://go.dev/doc/devel/release#policy
[godoc]: https://pkg.go.dev/connectrpc.com/otelconnect
[license]: https://github.com/connectrpc/otelconnect-go/blob/main/LICENSE
[opentelemetry.io]: https://opentelemetry.io/
[otel-rpc-conventions]: https://opentelemetry.io/docs/specs/semconv/rpc/
