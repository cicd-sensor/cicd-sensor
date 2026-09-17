package listener

import (
	"context"
	"fmt"
)

// Called only after successful Job-start authorization, outside registry locks.
// A preparation miss must not turn a successful Job start into a failed one.
func (l *Listener) prepareMachineHTTP(ctx context.Context) {
	if l.runnerType != "machine" || l.httpPreparation == nil {
		return
	}
	pid, err := requestPeerPID(ctx)
	if err != nil {
		return
	}
	if err := l.httpPreparation.Prepare(ctx, fmt.Sprintf("/proc/%d/root", pid), "job-start"); err != nil {
		l.logger.WarnContext(ctx, "http_preparation_job_start_incomplete", "error", err)
	}
}
