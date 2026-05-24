// Package sink defines manager-side output destinations for compressed batches.
package sink

import (
	"context"
	"errors"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

// ErrThrottled marks provider throttling that should be surfaced to agents as
// backpressure rather than as a generic downstream failure.
var ErrThrottled = errors.New("sink throttled")

const ContentTypeGzip = "application/gzip"

// Scope is the manager output scope segment carried by one ingest batch.
type Scope string

const (
	ScopeHost    Scope = "host"
	ScopeProject Scope = "project"
)

// FlushPolicy tells the agent how to batch one log type before sending it to
// the manager. It is manager-owned policy, not operator YAML.
type FlushPolicy struct {
	FlushThresholdBytes  uint32
	FlushIntervalSeconds uint32
}

// IngestLogBatch is the validated manager-side form of the proto ingest batch.
// Sinks decide how to route it: object storage builds a deterministic key,
// while Pub/Sub publishes the body with attributes.
type IngestLogBatch struct {
	LogType    logtype.LogType
	Identity   jobcontext.JobIdentity
	Scope      Scope
	FlushAt    time.Time
	ReceivedAt time.Time
	Body       []byte
}

// Sink is the minimal contract for writing one validated ingest batch.
type Sink interface {
	// Write delivers gzip-compressed bytes to the destination.
	Write(ctx context.Context, batch IngestLogBatch) error

	// Close releases client resources owned by the sink.
	Close() error

	// Name returns a human-readable identifier for logs and diagnostics.
	Name() string

	// FlushPolicy returns the agent-side batching policy preferred by this
	// destination for one log type.
	FlushPolicy(logKind logtype.LogType) FlushPolicy
}
