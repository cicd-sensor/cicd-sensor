# app-go

[![Build](https://github.com/bufbuild/app-go/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/bufbuild/app-go/actions/workflows/ci.yaml)
[![Report Card](https://goreportcard.com/badge/buf.build/go/app)](https://goreportcard.com/report/buf.build/go/app)
[![GoDoc](https://pkg.go.dev/badge/buf.build/go/app.svg)](https://pkg.go.dev/buf.build/go/app)
[![Slack](https://img.shields.io/badge/slack-buf-%23e01563)](https://buf.build/links/slack)

This library is the entry point for all Go applications at Buf. It abstracts away resources like
stdin, stdout, stderr, and args so that they can be tested outside of a global context, and provides
helpers for common functionality like reading config files, setting up flags, and adding sub-commands.

## Status: Beta

This library is in beta and is subject to change.

## Legal

Offered under the [Apache 2 license](https://github.com/bufbuild/app-go/blob/main/LICENSE).
