# interrupt-go

[![Build](https://github.com/bufbuild/interrupt-go/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/bufbuild/interrupt-go/actions/workflows/ci.yaml)
[![Report Card](https://goreportcard.com/badge/buf.build/go/interrupt)](https://goreportcard.com/report/buf.build/go/interrupt)
[![GoDoc](https://pkg.go.dev/badge/buf.build/go/interrupt.svg)](https://pkg.go.dev/buf.build/go/interrupt)
[![Slack](https://img.shields.io/badge/slack-buf-%23e01563)](https://buf.build/links/slack)

This is a small helper Go library that exposes two types:

- `interrupt.Signals`: All OS-specific interrupt signals. This extends `os.Interrupt` with `syscall.SIGTERM` in unix-like systems.
- `interrupt.Handle`: A simple function to provide interrupt signal handling on a `context.Context`.

This will typically be used at the highest levels of an application:

```go
func main() {
    // Handle returns a copy of the parent Context that is marked done
    // when an interrupt signal arrives or when the parent Context's
    // Done channel is closed, whichever happens first.
    //
    // Signal handling is unregistered automatically by this function when the
    // first interrupt signal arrives, which will restore the default interrupt
    // signal behavior of Go programs (to exit).

    ctx := interrupt.Handle(context.Background())

    // Use the ctx throughout the rest of your application.
    // ...
}
```

## Status: Stable

This library is stable.

## Legal

Offered under the [Apache 2 license](https://github.com/bufbuild/interrupt-go/blob/main/LICENSE).
