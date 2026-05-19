package sink

import (
	"errors"
	"testing"

	"github.com/aws/smithy-go"
)

func TestS3FlushPolicy(t *testing.T) {
	tests := []struct {
		name    string
		logKind LogKind
		want    FlushPolicy
	}{
		{
			name:    "detection is immediate",
			logKind: LogKindJobDetection,
			want:    FlushPolicy{FlushThresholdBytes: 1, FlushIntervalSeconds: 1},
		},
		{
			name:    "telemetry batches for object storage",
			logKind: LogKindJobRuntimeTelemetry,
			want:    FlushPolicy{FlushThresholdBytes: 4 * 1024 * 1024, FlushIntervalSeconds: 60},
		},
		{
			name:    "result is immediate",
			logKind: LogKindJobResult,
			want:    FlushPolicy{FlushThresholdBytes: 1, FlushIntervalSeconds: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (&s3Sink{}).FlushPolicy(tt.logKind); got != tt.want {
				t.Fatalf("FlushPolicy(%q): got %+v, want %+v", tt.logKind, got, tt.want)
			}
		})
	}
}

func TestIsS3Throttle(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "structured throttling code",
			err:  &smithy.GenericAPIError{Code: "SlowDown", Message: "slow down"},
			want: true,
		},
		{
			name: "structured non throttling code",
			err:  &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"},
		},
		{
			name: "string fallback throttling",
			err:  errors.New("request throttled by compatible storage"),
			want: true,
		},
		{
			name: "string fallback slowdown",
			err:  errors.New("SlowDown: please retry later"),
			want: true,
		},
		{
			name: "plain error",
			err:  errors.New("network unreachable"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isS3Throttle(tt.err); got != tt.want {
				t.Fatalf("isS3Throttle: got %v, want %v", got, tt.want)
			}
		})
	}
}
