package sink

import (
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

func TestAzureBlobFlushPolicy(t *testing.T) {
	tests := []struct {
		name    string
		logKind logtype.LogType
		want    FlushPolicy
	}{
		{
			name:    "detection is immediate",
			logKind: logtype.Detection,
			want:    FlushPolicy{FlushThresholdBytes: 1, FlushIntervalSeconds: 1},
		},
		{
			name:    "runtime event batches for object storage",
			logKind: logtype.RuntimeEvent,
			want:    FlushPolicy{FlushThresholdBytes: 128 * 1024 * 1024, FlushIntervalSeconds: 60},
		},
		{
			name:    "result is immediate",
			logKind: logtype.Summary,
			want:    FlushPolicy{FlushThresholdBytes: 1, FlushIntervalSeconds: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (&azureBlobSink{}).FlushPolicy(tt.logKind); got != tt.want {
				t.Fatalf("FlushPolicy(%q): got %+v, want %+v", tt.logKind, got, tt.want)
			}
		})
	}
}

func TestIsAzureBlobThrottle(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "server busy is throttling",
			err:  &azcore.ResponseError{ErrorCode: "ServerBusy", StatusCode: 503},
			want: true,
		},
		{
			name: "authorization failure is not throttling",
			err:  &azcore.ResponseError{ErrorCode: "AuthorizationFailure", StatusCode: 403},
		},
		{
			name: "plain error is not throttling",
			err:  errors.New("ServerBusy: please retry later"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAzureBlobThrottle(tt.err); got != tt.want {
				t.Fatalf("isAzureBlobThrottle: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseAzureBlobURI(t *testing.T) {
	tests := []struct {
		name          string
		uri           string
		wantService   string
		wantContainer string
		wantPrefix    string
		wantErr       string
	}{
		{
			name:          "full uri with prefix",
			uri:           "https://myaccount.blob.core.windows.net/cicd-sensor-logs/cicd-sensor/",
			wantService:   "https://myaccount.blob.core.windows.net",
			wantContainer: "cicd-sensor-logs",
			wantPrefix:    "cicd-sensor",
		},
		{
			name:          "container only",
			uri:           "https://myaccount.blob.core.windows.net/cicd-sensor-logs",
			wantService:   "https://myaccount.blob.core.windows.net",
			wantContainer: "cicd-sensor-logs",
			wantPrefix:    "",
		},
		{
			name:          "nested prefix",
			uri:           "https://myaccount.blob.core.windows.net/logs/team/cicd/",
			wantService:   "https://myaccount.blob.core.windows.net",
			wantContainer: "logs",
			wantPrefix:    "team/cicd",
		},
		{
			name:    "empty uri",
			uri:     "",
			wantErr: "azure_blob uri is required",
		},
		{
			name:    "wrong scheme",
			uri:     "azblob://cicd-sensor-logs/cicd-sensor/",
			wantErr: "azure_blob uri must use https:// scheme",
		},
		{
			name:    "http scheme rejected",
			uri:     "http://myaccount.blob.core.windows.net/cicd-sensor-logs/",
			wantErr: "azure_blob uri must use https:// scheme",
		},
		{
			name:    "missing container",
			uri:     "https://myaccount.blob.core.windows.net/",
			wantErr: "azure_blob uri must include a container name",
		},
		{
			name:    "query string rejected",
			uri:     "https://myaccount.blob.core.windows.net/cicd-sensor-logs/cicd-sensor/?sv=2021-01-01&sig=redacted",
			wantErr: "azure_blob uri must not include query or fragment",
		},
		{
			name:    "fragment rejected",
			uri:     "https://myaccount.blob.core.windows.net/cicd-sensor-logs/cicd-sensor/#frag",
			wantErr: "azure_blob uri must not include query or fragment",
		},
		{
			name:    "traversal prefix rejected",
			uri:     "https://myaccount.blob.core.windows.net/cicd-sensor-logs/../escape/",
			wantErr: "is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, container, prefix, err := parseAzureBlobURI(tt.uri)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !errContains(err, tt.wantErr) {
					t.Fatalf("error: got %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAzureBlobURI: %v", err)
			}
			if service != tt.wantService {
				t.Fatalf("service url: got %q, want %q", service, tt.wantService)
			}
			if container != tt.wantContainer {
				t.Fatalf("container: got %q, want %q", container, tt.wantContainer)
			}
			if prefix != tt.wantPrefix {
				t.Fatalf("prefix: got %q, want %q", prefix, tt.wantPrefix)
			}
		})
	}
}

func errContains(err error, sub string) bool {
	return err != nil && strings.Contains(err.Error(), sub)
}
