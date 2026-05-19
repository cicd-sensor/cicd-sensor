package sink

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPubSubFlushPolicy(t *testing.T) {
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
			name:    "telemetry batches briefly",
			logKind: LogKindJobRuntimeTelemetry,
			want:    FlushPolicy{FlushThresholdBytes: 256 * 1024, FlushIntervalSeconds: 5},
		},
		{
			name:    "result is immediate",
			logKind: LogKindJobResult,
			want:    FlushPolicy{FlushThresholdBytes: 1, FlushIntervalSeconds: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (&pubsubSink{}).FlushPolicy(tt.logKind); got != tt.want {
				t.Fatalf("FlushPolicy(%q): got %+v, want %+v", tt.logKind, got, tt.want)
			}
		})
	}
}

func TestIsPubSubThrottle(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "resource exhausted", err: status.Error(codes.ResourceExhausted, "quota"), want: true},
		{name: "unavailable is not classified here", err: status.Error(codes.Unavailable, "unavailable")},
		{name: "context canceled is caller shutdown", err: context.Canceled},
		{name: "deadline exceeded is caller timeout", err: context.DeadlineExceeded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPubSubThrottle(tt.err); got != tt.want {
				t.Fatalf("isPubSubThrottle: got %v, want %v", got, tt.want)
			}
		})
	}
}
