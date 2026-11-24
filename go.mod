module github.com/cicd-sensor/cicd-sensor

go 1.27.0

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2
	buf.build/go/protovalidate v1.4.0
	cel.dev/cel-go v0.33.2
	cloud.google.com/go/pubsub/v2 v2.9.0
	cloud.google.com/go/storage v1.71.0
	connectrpc.com/authn v0.2.0
	connectrpc.com/connect v1.21.1
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.24.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.15.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.8.3
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/config v1.33.19
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.10
	github.com/aws/smithy-go v1.28.9
	github.com/cilium/ebpf v0.22.0
	github.com/containerd/nri v0.12.5
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/go-jose/go-jose/v4 v4.1.9
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/go-containerregistry v0.22.1
	github.com/google/uuid v1.6.0
	github.com/moby/sys/mountinfo v0.7.3
	github.com/sigstore/cosign/v3 v3.1.4
	github.com/sigstore/sigstore-go v1.4.0
	go.opentelemetry.io/ebpf-profiler v0.0.202645
	go.yaml.in/yaml/v4 v4.0.0
	golang.org/x/net v0.62.0
	golang.org/x/oauth2 v0.38.0
	golang.org/x/sync v0.25.0
	golang.org/x/sys v0.50.0
	golang.org/x/text v0.44.0
	google.golang.org/api v0.315.0
	google.golang.org/protobuf v1.37.0-rc.1
)

require (
	buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go v1.36.12-20261002170247-538130002972.2 // indirect
	buf.build/gen/go/bufbuild/protodescriptor/protocolbuffers/go v1.36.12-20261012172039-ff528c23443f.2 // indirect
	buf.build/gen/go/bufbuild/registry/connectrpc/go/v2 v2.0.1-20261015154428-c661e2f1fba9.1 // indirect
	buf.build/gen/go/bufbuild/registry/protocolbuffers/go v1.36.12-20261015154428-c661e2f1fba9.2 // indirect
	buf.build/gen/go/pluginrpc/pluginrpc/protocolbuffers/go v1.36.12-20241007202033-cf42259fcbfc.2 // indirect
	buf.build/go/app v0.3.0 // indirect
	buf.build/go/bufplugin v0.11.1 // indirect
	buf.build/go/bufprivateusage v0.1.0 // indirect
	buf.build/go/interrupt v1.1.0 // indirect
	buf.build/go/protoyaml v0.7.0 // indirect
	buf.build/go/spdx v0.3.0 // indirect
	buf.build/go/standard v0.1.1-0.20260325175353-2b287e071df5 // indirect
	cel.dev/expr v0.25.3 // indirect
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.24.4 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.3.1 // indirect
	cloud.google.com/go/compute/metadata v0.10.0 // indirect
	cloud.google.com/go/iam v1.15.1 // indirect
	cloud.google.com/go/monitoring v1.30.0 // indirect
	connectrpc.com/connect/v2 v2.0.2 // indirect
	connectrpc.com/otelconnect v0.11.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.13.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/storage/internal v0.1.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20261006220739-8c912ac31dd4 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.10.1 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.62.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.62.0 // indirect
	github.com/Microsoft/go-winio v0.6.4 // indirect
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/apache/arrow-go/v18 v18.7.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.21.1 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.52.0 // indirect
	github.com/bufbuild/buf v1.75.0 // indirect
	github.com/bufbuild/protocompile v0.14.2-0.20261020145055-56248e843b50 // indirect
	github.com/bufbuild/protoplugin v0.0.0-20260414125817-25d1d281b46b // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cli/browser v1.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20260821105541-05f79448fa77 // indirect
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v29.9.1+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.10 // indirect
	github.com/docker/go-connections v0.8.2 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/elastic/go-freelru v0.16.0 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.39.1-0.20260819172001-e6e3fd93e4be // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-chi/chi/v5 v5.5.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v1.0.0 // indirect
	github.com/go-openapi/errors v0.22.9 // indirect
	github.com/go-openapi/jsonpointer v1.0.1 // indirect
	github.com/go-openapi/jsonreference v1.0.2 // indirect
	github.com/go-openapi/loads v0.25.3 // indirect
	github.com/go-openapi/runtime v0.33.3 // indirect
	github.com/go-openapi/runtime/server-middleware v0.33.3 // indirect
	github.com/go-openapi/spec v1.0.1 // indirect
	github.com/go-openapi/strfmt v0.27.4 // indirect
	github.com/go-openapi/swag/conv v0.29.2 // indirect
	github.com/go-openapi/swag/fileutils v0.29.2 // indirect
	github.com/go-openapi/swag/jsonutils v0.29.2 // indirect
	github.com/go-openapi/swag/loading v0.29.2 // indirect
	github.com/go-openapi/swag/mangling v0.29.2 // indirect
	github.com/go-openapi/swag/pools v0.29.2 // indirect
	github.com/go-openapi/swag/stringutils v0.29.2 // indirect
	github.com/go-openapi/swag/typeutils v0.29.2 // indirect
	github.com/go-openapi/swag/yamlutils v0.29.2 // indirect
	github.com/go-openapi/validate v1.0.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/gofrs/flock v0.13.1 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/certificate-transparency-go v1.4.0 // indirect
	github.com/google/flatbuffers v25.12.19+incompatible // indirect
	github.com/google/s2a-go v0.1.11 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.25 // indirect
	github.com/googleapis/gax-go/v2 v2.27.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.32.0 // indirect
	github.com/in-toto/attestation v1.2.0 // indirect
	github.com/in-toto/in-toto-golang v0.11.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jdx/go-netrc v1.0.0 // indirect
	github.com/jedisct1/go-minisign v0.0.0-20230811132847-661be99b8267 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/klauspost/pgzip v1.3.0 // indirect
	github.com/knqyf263/go-plugin v0.9.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/moby/api v1.56.1 // indirect
	github.com/moby/moby/client v0.6.2 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/nozzle/throttler v0.0.0-20180817012639-2ea982251481 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.3.0 // indirect
	github.com/petermattis/goid v0.0.0-20260918085751-abfca077860b // indirect
	github.com/pierrec/lz4/v4 v4.1.28 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.64.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sassoftware/relic/v8 v8.2.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.11.1 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/sigstore/protobuf-specs v0.5.2 // indirect
	github.com/sigstore/rekor v1.5.5 // indirect
	github.com/sigstore/rekor-tiles/v2 v2.4.0 // indirect
	github.com/sigstore/sigstore v1.11.1 // indirect
	github.com/sigstore/timestamp-authority/v2 v2.2.0 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spiffe/go-spiffe/v2 v2.8.2 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/theupdateframework/go-tuf v0.7.0 // indirect
	github.com/theupdateframework/go-tuf/v2 v2.4.2 // indirect
	github.com/tidwall/btree v1.8.2 // indirect
	github.com/transparency-dev/formats v0.1.1 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.lsp.dev/jsonrpc2 v0.10.0 // indirect
	go.lsp.dev/pkg v0.0.0-20210717090340-384b27a52fb2 // indirect
	go.lsp.dev/protocol v0.12.0 // indirect
	go.lsp.dev/uri v0.3.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.47.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.72.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.72.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/arch v0.32.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/genproto v0.0.0-20261012220534-4341edf3f941 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261110000943-09e21b237f2c // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261110000943-09e21b237f2c // indirect
	google.golang.org/grpc v1.85.0 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	mvdan.cc/xurls/v2 v2.6.0 // indirect
	pluginrpc.com/pluginrpc v0.6.0 // indirect
)

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	github.com/bufbuild/buf/cmd/buf
	github.com/cilium/ebpf/cmd/bpf2go
	google.golang.org/protobuf/cmd/protoc-gen-go
)
