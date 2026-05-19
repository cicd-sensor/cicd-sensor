package job

import "time"

// SetDeadlineAtForTesting rewinds the TTL deadline so cross-package tests can
// simulate an expired job without sleeping or rewinding the wall clock.
//
// This method is intended exclusively for tests in other packages (notably
// jobregistry tests of FinalizeExpiredJobs). Production code MUST NOT call it: TTL is
// otherwise immutable for the job lifetime. Same-package tests should mutate
// j.deadlineAt directly instead of going through this helper.
func (j *Job) SetDeadlineAtForTesting(deadline time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.deadlineAt = deadline
}
