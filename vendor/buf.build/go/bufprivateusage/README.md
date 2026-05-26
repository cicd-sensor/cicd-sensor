# bufprivateusage-go

[![Build](https://github.com/bufbuild/bufprivateusage-go/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/bufbuild/bufprivateusage-go/actions/workflows/ci.yaml)
[![Report Card](https://goreportcard.com/badge/buf.build/go/bufprivateusage)](https://goreportcard.com/report/buf.build/go/bufprivateusage)
[![GoDoc](https://pkg.go.dev/badge/buf.build/go/bufprivateusage.svg)](https://pkg.go.dev/buf.build/go/bufprivateusage)
[![Slack](https://img.shields.io/badge/slack-buf-%23e01563)](https://buf.build/links/slack)

This is a small helper Go library and command that we use at Buf to make it so that `private` packages within our Go libraries cannot be used outside of `github.com/bufbuild` or `buf.build/go` packages. This is our mechanism to make packages internal to our organization. This allows us to do breaking changes on organization-wide packages while knowing that no one will depend on them (and potentially have breaking changes in their code).

## Status: Alpha

This library will never be generally available, and is not stable. By design, you should not use this.

## Legal

Offered under the [Apache 2 license](https://github.com/bufbuild/bufprivateusage-go/blob/main/LICENSE).
