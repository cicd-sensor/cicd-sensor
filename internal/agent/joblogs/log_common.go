package joblogs

import (
	"log/slog"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

var logJSONMarshal = protojson.MarshalOptions{EmitDefaultValues: true}

type ScopeLogContext struct {
	Identity       jobcontext.JobIdentity
	Metadata       jobcontext.JobMetadata
	RunnerKind     string
	Scope          jobcontext.ScopeKind
	ConfigRevision string
}

func newLogID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

func uint64Counter(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func componentLogger(logger *slog.Logger, component string) *slog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return logger.With("component", component)
}
