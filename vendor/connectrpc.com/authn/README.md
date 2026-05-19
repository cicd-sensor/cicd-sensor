authn
=====
[![Build](https://github.com/connectrpc/authn-go/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/connectrpc/authn-go/actions/workflows/ci.yaml)
[![Report Card](https://goreportcard.com/badge/connectrpc.com/authn)](https://goreportcard.com/report/connectrpc.com/authn)
[![GoDoc](https://pkg.go.dev/badge/connectrpc.com/authn.svg)](https://pkg.go.dev/connectrpc.com/authn)
[![Slack](https://img.shields.io/badge/slack-buf-%23e01563)][slack]

`connectrpc.com/authn` provides authentication middleware for
[Connect](https://connectrpc.com/). It works with any authentication scheme
(including HTTP basic authentication, cookies, bearer tokens, and mutual TLS),
and it's carefully designed to minimize the resource consumption of
unauthenticated RPCs. Middleware built with `authn` covers both unary and
streaming RPCs made with the Connect, gRPC, and gRPC-Web protocols.

For more on Connect, see the [announcement blog post][blog], the documentation
on [connectrpc.com][docs] (especially the [Getting Started] guide for Go), the
[demo service][examples-go], or the [protocol specification][protocol].

## A small example

Curious what all this looks like in practice? From a [Protobuf
schema](internal/proto/authn/ping/v1/ping.proto), we generate [a small RPC
package](internal/gen/authn/ping/v1/pingv1connect/ping.connect.go). Using that
package, we can build a server and wrap it with some basic authentication:

```go
package main

import (
  "context"
  "crypto/subtle"
  "net/http"

  "connectrpc.com/authn"
  "connectrpc.com/authn/internal/gen/authn/ping/v1/pingv1connect"
)

func authenticate(_ context.Context, req *http.Request) (any, error) {
  username, password, ok := req.BasicAuth()
  if !ok {
    return nil, authn.Errorf("invalid authorization")
  }
  if !equal(password, "open-sesame") {
    return nil, authn.Errorf("invalid password")
  }
  // The request is authenticated! We can propagate the authenticated user to
  // Connect interceptors and services by returning it: the middleware we're
  // about to construct will attach it to the context automatically.
  return username, nil
}

func equal(left, right string) bool {
  // Using subtle prevents some timing attacks.
  return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func main() {
  mux := http.NewServeMux()
  service := &pingv1connect.UnimplementedPingServiceHandler{}
  mux.Handle(pingv1connect.NewPingServiceHandler(service))

  middleware := authn.NewMiddleware(authenticate)
  handler := middleware.Wrap(mux)
  http.ListenAndServe("localhost:8080", handler)
}
```

Cookie and token-based authentication is similar. Mutual TLS is a bit more
complex, but [pkg.go.dev][godoc] includes a complete example.

## Ecosystem

* [connect-go]: the Go implementation of Connect's RPC runtime
* [examples-go]: service powering demo.connectrpc.com, including bidi streaming
* [grpchealth]: gRPC-compatible health checks
* [grpcreflect]: gRPC-compatible server reflection
* [cors]: CORS support for Connect servers
* [connect-es]: Type-safe APIs with Protobuf and TypeScript
* [conformance]: Connect, gRPC, and gRPC-Web interoperability tests

## Status: Unstable

This module isn't stable yet, but it's fairly small &mdash; we expect to reach
a stable release quickly.

It supports the three most recent major releases of Go. Keep in mind that [only
the last two releases receive security patches][go-support-policy].

Within those parameters, `authn` follows semantic versioning. We will _not_
make breaking changes in the 1.x series of releases.

## Legal

Offered under the [Apache 2 license][license].

[Getting Started]: https://connectrpc.com/docs/go/getting-started
[blog]: https://buf.build/blog/connect-a-better-grpc
[conformance]: https://github.com/connectrpc/conformance
[connect-es]: https://github.com/connectrpc/connect-es
[connect-go]: https://github.com/connectrpc/connect-go
[cors]: https://github.com/connectrpc/cors-go
[docs]: https://connectrpc.com
[examples-go]: https://github.com/connectrpc/examples-go
[go-support-policy]: https://golang.org/doc/devel/release#policy
[godoc]: https://pkg.go.dev/connectrpc.com/authn
[grpchealth]: https://github.com/connectrpc/grpchealth-go
[grpcreflect]: https://github.com/connectrpc/grpcreflect-go
[license]: https://github.com/connectrpc/authn-go/blob/main/LICENSE
[protocol]: https://connectrpc.com/docs/protocol
[slack]: https://buf.build/links/slack
