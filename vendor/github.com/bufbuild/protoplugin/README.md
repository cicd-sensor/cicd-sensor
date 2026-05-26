protoplugin
==============

[![Build](https://github.com/bufbuild/protoplugin/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/bufbuild/protoplugin/actions/workflows/ci.yaml)
[![Report Card](https://goreportcard.com/badge/github.com/bufbuild/protoplugin)](https://goreportcard.com/report/github.com/bufbuild/protoplugin)
[![GoDoc](https://pkg.go.dev/badge/github.com/bufbuild/protoplugin.svg)](https://pkg.go.dev/github.com/bufbuild/protoplugin)
[![Slack](https://img.shields.io/badge/slack-buf-%23e01563)](https://buf.build/links/slack)

The premise of this library is pretty simple: writing your [protoc](https://github.com/protocolbuffers/protobuf)
plugins is a powerful way to make Protobuf even more useful, but to do so, we all have to write the same
boilerplate scaffolding over and over again. Additionally, you want to make sure that you have a
[`CodeGeneratorRequest`](https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/compiler/plugin.proto)
that had sensible validations applied to it, and that you produce a valid
[CodeGeneratorResponse](https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/compiler/plugin.proto).
It's really easy to produce a `CodeGeneratorResponse` that `protoc` or [buf](https://github.com/bufbuild/buf) will happily consume, but is actually invalid and will result in unexpected generated code.

`protoplugin` takes care of all of this for you, and nothing more. `protoplugin` makes authoring `protoc` plugins
in Go super-simple. `protoplugin` will:

- Deal with all the boilerplate of consuming `CodeGeneratorRequests` and `CodeGeneratorResponses` for you,
  providing you with a simple [Handler](https://pkg.go.dev/github.com/bufbuild/protoplugin#Handler) interface
  to implement.
- Validate that the `CodeGeneratorRequest` consumed matches basic expectations.
- Help you create a `CodeGeneratorResponse` that is valid, or give you an error otherwise.

The validation performed takes into account years of experience we've had here at [Buf](https://buf.build) to
handle edge cases you've never thought about - the same code backs the execution of plugins within the
`buf` compiler, and has dealt with handling plugins that misbehave in ways we never would have expected.

`protoplugin` is also ready for [Protobuf Editions](https://protobuf.dev/editions) from day one, helping you
navigate this new Protobuf functionality with ease.

`protoplugin` has a single non-test dependency, on
`google.golang.org/protobuf` - all other dependencies in [`go.mod`](go.mod) are for `protoplugin`'s own
tests, and will not result in additional dependencies in your code.

If you are authoring `protoc` plugins in Go that do anything other than produce `.go` files,
you should use `protoplugin`. It's the foundational library you need, and it doesn't include anything
you don't want.

If you are authoring `protoc` plugins that produce `.go` files, you
should use [protogen](https://pkg.go.dev/google.golang.org/protobuf/compiler/protogen), as it has
Go-specific helpers, such as dealing with Go import paths, and handling the standard Go
`protoc` plugin flags like `paths=source_relative`. However, `protogen` is very Go-specific -
the interfaces exposed don't really make sense outside of generating `.go` files, and you specifically
do not want most plugins to expose the standard Go `protoc` plugin flags. If you'd like to use `protogen`
but also take advantage of `protoplugin`'s hardening, it's very easy to wrap `protogen` with
`protoplugin` - see the [protoc-gen-protogen-simple](internal/examples/protoc-gen-protogen-simple/main.go)
example in this repository.

## Protoplugin Handlers

Implementing a plugin with `protoplugin` is as simple as implementing a `Handler`. The `Handler`
is then typically invoked via `protoplugin.Main`, or if doing testing, via `protoplugin.Run` (which
gives you control over `args, stdin, stdout, stderr`).

Here's a simple plugin that just prints the top-level message names for all files in `file_to_generate`:

```go
// Package main implements a very simple plugin that just outputs text files
// with the names of the top-level messages in each file.
//
// Example: if a/b.proto had top-level messages C, D, the file "a/b.proto.txt" would be
// outputted, containing "C\nD\n".
package main

import (
	"context"
	"strings"

	"github.com/bufbuild/protoplugin"
)

func main() {
	protoplugin.Main(protoplugin.HandlerFunc(handle))
}

func handle(
	_ context.Context,
  _ protoplugin.PluginEnv,
	responseWriter protoplugin.ResponseWriter,
	request protoplugin.Request,
) error {
	// Set the flag indicating that we support proto3 optionals. We don't even use them in this
	// plugin, but protoc will error if it encounters a proto3 file with an optional but the
	// plugin has not indicated it will support it.
	responseWriter.SetFeatureProto3Optional()

	fileDescriptors, err := request.FileDescriptorsToGenerate()
	if err != nil {
		return err
	}
	for _, fileDescriptor := range fileDescriptors {
		messages := fileDescriptor.Messages()
		topLevelMessageNames := make([]string, messages.Len())
		for i := 0; i < messages.Len(); i++ {
			topLevelMessageNames[i] = string(messages.Get(i).Name())
		}
		// Add the response file to the response.
		responseWriter.AddFile(
			fileDescriptor.Path()+".txt",
			strings.Join(topLevelMessageNames, "\n")+"\n",
		)
	}

	return nil
}
```

**For 99% of plugin authors, this is all you need to do** - loop over the `GeneratedFileDescriptors`, add files with `AddFile`, and if you have errors, add errors with `SetError`. That's it.

A `Handler` takes a [`Request`](https://pkg.go.dev/github.com/bufbuild/protoplugin#Request), and expects a response
to be written to the [`ResponseWriter`](https://pkg.go.dev/github.com/bufbuild/protoplugin#ResponseWriter).

### Requests

A `Request` wraps a `CodeGeneratorRequest`, but performs common-sense validation. The `Handler` can assume
all of the following is true:

TODO: Update with latest validation

- The `CodeGeneratorRequest` given to the plugin was not nil.
- `file_to_generate` and `proto_file` were not empty.
- Each `FileDescriptorProto` in `proto_file` will have a valid path (see below) as the `name` field.
- Each value of `file_to_generate` will be a valid path.
- Each value of `file_to_generate` will have a corresponding value in `proto_file`.
- (For editions) if `source_file_descriptors` is not empty, each `FileDescriptorProto` in
  `source_file_descriptors` will have a valid path as the name field.
- (For editions) if `source_file_descriptors` is not empty, the values of `file_to_generate` will
  have a 1-1 mapping to the names in `source_file_descriptors`.

Paths are considered valid if they are non-empty, relative, use '/' as the path separator, do not jump context (`..`),
and have `.proto` as the file extension.

If any of these validations fail, the plugin will exit with a non-zero exit code.

This is all per the spec of `CodeGeneratorRequest`, but you'd be surprised what producers of
`CodeGeneratorRequests` (including `protoc` and `buf`) can do - compilers are not immune to bugs!

A Request exposes two ways to get the file information off of the `CodeGeneratorRequest`:

- Via the rich [protoreflect API](https://pkg.go.dev/google.golang.org/protobuf@v1.32.0/reflect/protoreflect)
  by the types [`protoreflect.FileDescriptor`](https://pkg.go.dev/google.golang.org/protobuf@v1.32.0/reflect/protoreflect#FileDescriptor)
  and [`*protoregistry.Files`](https://pkg.go.dev/google.golang.org/protobuf@v1.32.0/reflect/protoregistry#Files)
- Directly via the `FileDescriptorProtos`.

The methods `FileDescriptorsToGenerate` and `FileDescriptorProtosToGenerate` will provide file information
only for those files specified in `file_to_generate`, while `AllFiles` and `AllFileDescriptorProtos`
will provide file information for all files in `proto_file`.

See [protoc-gen-protoreflect-simple](internal/examples/protoc-gen-protoreflect-simple/main.go) for a simple
example using the `protoreflect` API, and [protoc-gen-simple](internal/examples/protoc-gen-simple/main.go)
for a simple example using the `FileDescriptorProtos` directly.

Additionally, if the option `WithSourceRetentionOptions` is specified, any of these methods will return the files
with source-retention options automatically. This is a new Editions feature that most plugin authors do not
need to be concerned with yet.

A `Request` also exposes the `Parameters` and `CompilerVersion` specified on the `CodeGeneratorRequest`,
the latter with validation the version is valid. Additionally, if you need low-level access, a
`CodeGeneratorRequest` method is provided to expose the underlying `CodeGeneratorRequest`

### ResponseWriters

A `ResponseWriter` builds `CodeGeneratorResponses` for you. The most common methods you will use:

- `AddFile`: Add a new file with content.
- `SetError`: Add to the error message that will be propagated to the compiler.
- `SetFeatureProto3Optional`: Denote that your plugin handles `optional` in `proto3` (all new plugins should set this).
- `SetFeatureSupportsEditions`: Denote that you support editions (most plugins will not yet).

A `ResponseWriter` also provide low-level access for advanced plugins that need to build the `CodeGeneratorResponse`
more directly:

- `AddCodeGeneratorResponseFiles`: Add `CodeGeneratorResponse.File`s directly. May be needed when using i.e.
  insertion points.
- `SetSupportedFeatures`: Set supported features directly.
- `SetMinimumEdition/SetMaximumEdition`: directly set the minimum and maximum Edition supported.

For most authors, however, you should use the common methods.

`ResponseWriters` will also perform validation for you. The following must be true:

- All files added must have non-empty, relative paths that use '/' as the path separator and do not jump context (`..`).
- The minimum Edition must be less than or equal to the maximum Edition.

If any of these validations fail, the plugin will exit with a non-zero exit code.

Errors or warnings will also be produced if:

- Files do not have unique names. `protoc` will continue on without erroring if this happens, but will just
  silently drop all occurrences of the file after the name has already been seen. In almost all cases,
  a duplicate name is plugin authoring issue, and here at Buf, we've seen a lot of plugins have this issue!
- Any file path is not cleaned.

By default, these are errors, however if `WithLenientValidation` is set, these will be warnings.

## What this library is not

This library is not a full-fledged plugin authoring framework with language-specific interfaces,
and doesn't intend to be. The only language-specific framework in wide use that we are aware of:

- [`protogen`](https://pkg.go.dev/google.golang.org/protobuf/compiler/protogen): As mentioned in the introduction,
  `protogen` is the standard way to write plugins that produce `.go` files, however it is specific to this purpose -
  if you are writing a plugin in Go that produces Ruby, Python, YAML, etc, you are better-served without the
  Go-specific interfaces, and the Go-specific `protoc` plugin flags that all `protogen`-authored plugins
  have added.
- [`@bufbuild/protoplugin`](https://www.npmjs.com/package/@bufbuild/protoplugin):
  framework for writing JavaScript/TypeScript plugins that we also authored. It's great! And it backs
  [`protobuf-es`](https://github.com/bufbuild/protobuf-es) and [`connect-es`](https://github.com/connectrpc/connect-es).

It would be great if there were other language-specific frameworks out there, and perhaps we will get to it
some day. However, `protoplugin` is meant to be the foundational layer that every Go-authored plugin wants:
it gives you the basics, so you don't have to write them again and again.

## Status: Alpha

This module is still being developed and may change.

## Legal

Offered under the [Apache 2 license](https://github.com/bufbuild/protoplugin/blob/main/LICENSE).
