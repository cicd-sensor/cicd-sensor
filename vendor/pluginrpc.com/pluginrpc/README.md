# pluginrpc-go

[![Build](https://github.com/pluginrpc/pluginrpc-go/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/pluginrpc/pluginrpc-go/actions/workflows/ci.yaml)
[![Report Card](https://goreportcard.com/badge/pluginrpc.com/pluginrpc)](https://goreportcard.com/report/pluginrpc.com/pluginrpc)
[![GoDoc](https://pkg.go.dev/badge/pluginrpc.com/pluginrpc.svg)](https://pkg.go.dev/pluginrpc.com/pluginrpc)
[![Slack](https://img.shields.io/badge/slack-buf-%23e01563)](https://buf.build/links/slack)

The Golang library for [PluginRPC](https://github.com/pluginrpc/pluginrpc).

The [pluginrpc.com/pluginrpc](https://pkg.go.dev/pluginrpc.com/pluginrpc) library provides all the
primitives necessary to operate with the PluginRPC ecosystem. The `protoc-gen-pluginrpc-go` plugin
generates stubs for Protobuf services to work with PluginRPC. It makes authoring and consuming
plugins based on Protobuf services incredibly simple.

For more on the motivation behind PluginRPC, see the
[github.com/pluginrpc/pluginrpc](https://github.com/pluginrpc/pluginrpc) documentation.

For a full example, see the [internal/example](internal/example) directory. This contains:

- [proto/pluginrpc/example/v1](internal/example/proto/pluginrpc/example/v1): An Protobuf package
  that contains an example Protobuf service `EchoService`.
- [gen/pluginrpc/example/v1](internal/example/gen/pluginrpc/example/v1): The generated code from
  `protoc-gen-go` and `protoc-gen-pluginrpc-go` for the example Protobuf Package.
- [echo-plugin](internal/example/cmd/echo-plugin): An implementation of a PluginRPC plugin for
  `EchoService`.
- [echo-request-client](internal/example/cmd/echo-request-client): A simple client that calls the
  `EchoRequest` RPC via invoking `echo-plugin`.
- [echo-list-client](internal/example/cmd/echo-request-client): A simple client that calls the
  `EchoList` RPC via invoking `echo-plugin`.
- [echo-error-client](internal/example/cmd/echo-error-client): A simple client that calls the
  `EchoError` RPC via invoking `echo-plugin`.

## Usage

Install the `protoc-gen-go` and `protoc-gen-pluginrpc-go` plugins:

```bash
$ go install \
    google.golang.org/protobuf/cmd/protoc-gen-go@latest \
    pluginrpc.com/pluginrpc/cmd/protoc-gen-pluginrpc-go@latest
```

Generate stubs. The easiest way to do so is by using [buf](github.com/bufbuild/buf). See Buf's
[generation tutorial] for more details on setting up generation. You'll likely need a `buf.gen.yaml`
file that looks approximately like the following:

```yaml
version: v2
inputs:
  # Or wherever your .proto files live
  - directory: proto
managed:
  enabled: true
  override:
    - file_option: go_package_prefix
      # Replace github.com/acme/foo with the name of your Golang module
      value: github.com/acme/foo/gen
plugins:
  - local: protoc-gen-go
    out: gen
    opt: paths=source_relative
  - local: protoc-gen-pluginrpc-go
    out: gen
    opt: paths=source_relative
```

Build your plugin. See [echo-plugin](internal/example/cmd/echo-plugin) for a full example. Assuming
you intend to expose the `EchoService` as a plugin, your code will look something like this:

```go
func main() {
	pluginrpc.Main(newServer)
}

func newServer() (pluginrpc.Server, error) {
	spec, err := examplev1pluginrpc.EchoServiceSpecBuilder{
		// Note that EchoList does not have optional args and will default to path being the only arg.
		//
		// This means that the following commands will invoke their respective procedures:
		//
		//   echo-plugin echo request
		//   echo-plugin /pluginrpc.example.v1.EchoService/EchoList
		//   echo-plugin echo error
		EchoRequest: []pluginrpc.ProcedureOption{pluginrpc.ProcedureWithArgs("echo", "request")},
		EchoError:   []pluginrpc.ProcedureOption{pluginrpc.ProcedureWithArgs("echo", "error")},
	}.Build()
	if err != nil {
		return nil, err
	}
	serverRegistrar := pluginrpc.NewServerRegistrar()
	echoServiceServer := examplev1pluginrpc.NewEchoServiceServer(pluginrpc.NewHandler(spec), echoServiceHandler{})
	examplev1pluginrpc.RegisterEchoServiceServer(serverRegistrar, echoServiceServer)
	return pluginrpc.NewServer(spec, serverRegistrar)
}

type echoServiceHandler struct{}

func (echoServiceHandler) EchoRequest(_ context.Context, request *examplev1.EchoRequestRequest) (*examplev1.EchoRequestResponse, error) {
    ...
}

func (echoServiceHandler) EchoList(context.Context, *examplev1.EchoListRequest) (*examplev1.EchoListResponse, error) {
    ...
}

func (echoServiceHandler) EchoError(_ context.Context, request *examplev1.EchoErrorRequest) (*examplev1.EchoErrorResponse, error) {
    ...
}
```

Invoke your plugin. You'll create a client that points to your plugin. See
[echo-request-client](internal/example/cmd/echo-request-client) for a full example. Invocation will
look something like this:

```go
client := pluginrpc.NewClient(pluginrpc.NewExecRunner("echo-plugin"))
echoServiceClient, err := examplev1pluginrpc.NewEchoServiceClient(client)
if err != nil {
    return err
}
response, err := echoServiceClient.EchoRequest(
    context.Background(),
    &examplev1.EchoRequestRequest{
        ...
    },
)
```

See [pluginrpc_test.go](pluginrpc_test.go) for an example of how to test plugins.

## Plugin Options

The `protoc-gen-pluginrpc-go` has an option `streaming` that specifies how to handle streaming RPCs.
PluginRPC does not support streaming methods. There are three valid values for `streaming`: `error`,
`warn`, `ignore`. The default is `warn`:

- `streaming=error`: The plugin will error if a streaming method is encountered.
- `streaming=warn`: The plugin will produce a warning to stderr if a streaming method is
  encountered.
- `streaming=ignore`: The plugin will ignore streaming methods and not produce a warning.

In the case of `warn` or `ignore`, streaming RPCs will be skipped and no functions will be generated
for them. If a service only has streaming RPCs, no interfaces will be generated for this service. If
a file only has services with only streaming RPCs, no file will be generated.

Additionally, `protoc-gen-pluginrpc-go has all the
[standard Go plugin options](https://pkg.go.dev/google.golang.org/protobuf@v1.34.2/compiler/protogen):

- `module=<module>`
- `paths={import,source_relative}`
- `annotate_code={true,false}`
- `M<file>=<package>`


## Status: Beta

This framework is in active development, and should not be considered stable.

## Legal

Offered under the [Apache 2 license](https://github.com/pluginrpc/pluginrpc-go/blob/main/LICENSE).
