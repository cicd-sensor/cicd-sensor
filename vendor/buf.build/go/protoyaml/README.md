# ProtoYAML

[![Build](https://github.com/bufbuild/protoyaml-go/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/bufbuild/protoyaml-go/actions/workflows/ci.yaml)
[![Report Card](https://goreportcard.com/badge/buf.build/go/protoyaml)](https://goreportcard.com/report/buf.build/go/protoyaml)
[![GoDoc](https://pkg.go.dev/badge/buf.build/go/protoyaml.svg)](https://pkg.go.dev/buf.build/go/protoyaml)

Marshal and unmarshal Protocol Buffers as YAML. Provides fine-grained error details with file, line, column and snippet information.

Fully compatible with [protojson](https://github.com/protocolbuffers/protobuf-go/tree/master/encoding/protojson).

## Usage

```go
package main

import (
  "log"

  "buf.build/go/protoyaml"
)

func main() {
  // Marshal a proto message to YAML.
  yamlBytes, err := protoyaml.Marshal(
    &pb.MyMessage{
      MyField: "hello world",
    },
  )
  if err != nil {
    log.Fatal(err)
  }

  // Unmarshal a proto message from YAML.
  options := protoyaml.UnmarshalOptions{
    Path: "testdata/basic.proto3test.yaml",
  }
  var myMessage pb.MyMessage
  if err := options.Unmarshal(yamlBytes, &myMessage); err != nil {
    log.Fatal(err)
  }
}
```

ProtoYAML returns either `nil` or an error with a detailed message. For every error found in the file, the error
message includes the file name (if `Path` is set on `UnmarshalOptions`), line number, column number, and snippet
of the YAML that caused the error. For example, when unmarshalling the following YAML file:

```yaml
values:
  - single_bool: true
  - single_bool: false
  - single_bool: 1
  - single_bool: 0
  - single_bool: "true"
  - single_bool: "false"
  - single_bool: True
  - single_bool: False
  - single_bool: TRUE
  - single_bool: FALSE
  - single_bool: yes
  - single_bool: no
```

The following errors are returned:

```
testdata/basic.proto3test.yaml:5:18: expected bool, got "1"
   5 |   - single_bool: 1
     | .................^
testdata/basic.proto3test.yaml:6:18: expected bool, got "0"
   6 |   - single_bool: 0
     | .................^
testdata/basic.proto3test.yaml:7:18: expected tag !!bool, got !!str
   7 |   - single_bool: "true"
     | .................^
testdata/basic.proto3test.yaml:8:18: expected tag !!bool, got !!str
   8 |   - single_bool: "false"
     | .................^
testdata/basic.proto3test.yaml:9:18: expected bool, got "True"
   9 |   - single_bool: True
     | .................^
testdata/basic.proto3test.yaml:10:18: expected bool, got "False"
  10 |   - single_bool: False
     | .................^
testdata/basic.proto3test.yaml:11:18: expected bool, got "TRUE"
  11 |   - single_bool: TRUE
     | .................^
testdata/basic.proto3test.yaml:12:18: expected bool, got "FALSE"
  12 |   - single_bool: FALSE
     | .................^
testdata/basic.proto3test.yaml:13:18: expected bool, got "yes"
  13 |   - single_bool: yes
     | .................^
testdata/basic.proto3test.yaml:14:18: expected bool, got "no"
  14 |   - single_bool: no
     | .................^
```

Only `true` and `false` are valid values for the `single_bool` field.

For more examples, see the [internal/testdata](internal/testdata) directory.

## Validation

ProtoYAML can integrate with external validation libraries such as
[Protovalidate](https://github.com/bufbuild/protovalidate-go) to provide additional rich error
information. Simply provide a `Validator` to the `UnmarshalOptions`:

```go
package main

import (
  "log"

  "buf.build/go/protoyaml"
  "buf.build/go/protovalidate"
)

func main() {
  validator, err := protovalidate.NewValidator()
  if err != nil {
    log.Fatal(err)
  }

  var myMessage pb.MyMessage
  options := protoyaml.UnmarshalOptions{
    Path: "testdata/basic.proto3test.yaml",
    Validator: validator,
  }
  if err := options.Unmarshal(yamlBytes, &myMessage); err != nil {
    log.Fatal(err)
  }
}
```

The errors produced by the `Validator` will show up along side the ProtoYAML errors. For example:

```
testdata/validate.validate.yaml:4:18 cases[2].float_gt_lt: value must be greater than 0 and less than 10 (float.gt_lt)
   4 |   - float_gt_lt: 10.5
     | .................^
```

## Status: Beta

ProtoYAML is not yet stable. However, the final shape is unlikely to change drastically—future edits will be somewhat minor.

## Legal

Offered under the [Apache 2 license](https://github.com/bufbuild/protoyaml-go/blob/main/LICENSE)
