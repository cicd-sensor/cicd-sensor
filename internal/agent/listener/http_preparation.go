package listener

import (
	"context"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

// Called only after successful Job-start authorization, outside registry locks.
// A preparation miss must not turn a successful Job start into a failed one.
func (l *Listener) prepareMachineHTTP(ctx context.Context) {
	if l.runnerType != "machine" || l.httpPreparation == nil {
		return
	}
	if err := l.httpPreparation.Prepare(ctx, "/", nil, kernelio.HTTPPreparationOptions{Source: "job-start", Pin: true}); err != nil {
		l.logger.WarnContext(ctx, "http_preparation_job_start_incomplete", "error", err)
	}
}
