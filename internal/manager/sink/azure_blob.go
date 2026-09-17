package sink

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

type azureBlobSink struct {
	client     *azblob.Client
	serviceURL string
	container  string
	prefix     string
}

const (
	azureBlobImmediateFlushBytes   = 1
	azureBlobImmediateFlushSeconds = 1

	// Uncompressed JSONL threshold; see s3.go for the sizing rationale.
	azureBlobRuntimeEventFlushBytes   = 128 * 1024 * 1024
	azureBlobRuntimeEventFlushSeconds = 60
)

// NewAzureBlob creates an Azure Blob Storage-backed Sink using the Azure
// default credential chain. uri must be the full blob service URL including
// the container and optional key prefix, e.g.
// https://myaccount.blob.core.windows.net/container/prefix/; the host is the
// account endpoint, the first path segment is the container, and the rest is
// the object key prefix. Query strings and fragments are rejected so SAS URLs
// cannot smuggle credentials through manager.yaml.
func NewAzureBlob(ctx context.Context, uri string) (Sink, error) {
	serviceURL, container, prefix, err := parseAzureBlobURI(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid azure_blob uri: %w", err)
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create azure credential: %w", err)
	}
	client, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create azure blob client: %w", err)
	}
	return &azureBlobSink{
		client:     client,
		serviceURL: serviceURL,
		container:  container,
		prefix:     prefix,
	}, nil
}

func (s *azureBlobSink) Write(ctx context.Context, batch IngestLogBatch) error {
	key, err := objectKey(batch)
	if err != nil {
		return err
	}
	blobName := joinPrefix(s.prefix, key)
	_, err = s.client.UploadBuffer(ctx, s.container, blobName, batch.Body, &azblob.UploadBufferOptions{
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType:        to.Ptr(ContentTypeGzip),
			BlobContentDisposition: to.Ptr(`attachment; filename="` + path.Base(blobName) + `"`),
		},
		Metadata: map[string]*string{"flush_at": to.Ptr(formatFlushAt(batch.FlushAt))},
	})
	if err != nil {
		if isAzureBlobThrottle(err) {
			return fmt.Errorf("%w: %v", ErrThrottled, err)
		}
		return fmt.Errorf("upload azure blob: %w", err)
	}
	return nil
}

func (s *azureBlobSink) Close() error {
	return nil
}

func (s *azureBlobSink) Name() string {
	name := s.serviceURL + "/" + s.container
	if s.prefix != "" {
		name += "/" + s.prefix
	}
	return name
}

func (s *azureBlobSink) FlushPolicy(logKind logtype.LogType) FlushPolicy {
	switch logKind {
	case logtype.RuntimeEvent:
		return FlushPolicy{
			FlushThresholdBytes:  azureBlobRuntimeEventFlushBytes,
			FlushIntervalSeconds: azureBlobRuntimeEventFlushSeconds,
		}
	default:
		return FlushPolicy{
			FlushThresholdBytes:  azureBlobImmediateFlushBytes,
			FlushIntervalSeconds: azureBlobImmediateFlushSeconds,
		}
	}
}

// isAzureBlobThrottle reports whether err is Azure Storage server-side
// throttling (ServerBusy) that should surface as backpressure. The check is
// structured only: bloberror.HasCode inspects the SDK's typed error, so there
// is no brittle string fallback.
func isAzureBlobThrottle(err error) bool {
	return bloberror.HasCode(err, bloberror.ServerBusy)
}

// parseAzureBlobURI splits a full blob service URL like
// https://account.blob.core.windows.net/container/prefix/ into the service
// URL (scheme + host), container name, and object key prefix. The prefix may
// be empty and is validated with fs.ValidPath to reject traversal segments,
// mirroring parseObjectURI. Query strings and fragments are rejected so SAS
// URLs never land in manager.yaml.
func parseAzureBlobURI(uri string) (serviceURL, container, prefix string, err error) {
	if uri == "" {
		return "", "", "", fmt.Errorf("azure_blob uri is required")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", "", fmt.Errorf("parse azure_blob uri: %w", err)
	}
	if u.Scheme != "https" {
		return "", "", "", fmt.Errorf("azure_blob uri must use https:// scheme")
	}
	if u.Host == "" {
		return "", "", "", fmt.Errorf("azure_blob uri must include the storage account host")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", "", fmt.Errorf("azure_blob uri must not include query or fragment")
	}
	container, prefix, _ = strings.Cut(strings.Trim(u.Path, "/"), "/")
	if container == "" {
		return "", "", "", fmt.Errorf("azure_blob uri must include a container name")
	}
	if prefix != "" && !fs.ValidPath(prefix) {
		return "", "", "", fmt.Errorf("azure_blob uri prefix %q is invalid: must be UTF-8 and contain no \".\", \"..\", or empty path segments", prefix)
	}
	return u.Scheme + "://" + u.Host, container, prefix, nil
}
