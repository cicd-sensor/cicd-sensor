package joblogs

import (
	"log/slog"
	"math"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// Drops zero-valued fields so unset provider-specific keys disappear.
var logJSONMarshal = protojson.MarshalOptions{EmitDefaultValues: false}

type ScopeLogContext struct {
	Identity       jobcontext.JobIdentity
	Metadata       jobcontext.JobMetadata
	RunnerType     string
	Scope          jobcontext.ScopeType
	ConfigRevision string
}

func newLogID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

func uint32Counter(n int64) uint32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}

// AbsentSentinel marks fields that are emitted even when no value exists,
// so readers can tell "nothing was loaded" apart from a real value.
const AbsentSentinel = "(none)"

func configRevisionOrAbsent(s string) string {
	if s == "" {
		return AbsentSentinel
	}
	return s
}

func componentLogger(logger *slog.Logger, component string) *slog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return logger.With("component", component)
}
