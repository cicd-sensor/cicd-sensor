// Package job owns the per-job runtime state: identity, metadata, runner type,
// lifecycle transitions, the per-job event worker, and the immutable evaluation bundle
// that drives the rule hot path. JobRegistry constructs Job instances and
// JobScopeState fills in scope-local rule data; this package keeps the
// boundary between those two concerns explicit so neither side can mutate the
// other's state.
package job

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/evaluation"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
)

// JobState represents the lifecycle state of a job.
type JobState string

const (
	JobStateRunning JobState = "running"
	JobStateClosing JobState = "closing"
)

// DefaultTTL is the maximum lifetime of a job before forced finalization.
const DefaultTTL = 24 * time.Hour

var (
	// ErrHostScopeRequired reports that SetHostScope received a nil scope.
	ErrHostScopeRequired = errors.New("host scope is required")
	// ErrProjectScopeRequired reports that SetProjectScope received a nil scope.
	ErrProjectScopeRequired = errors.New("project scope is required")
	// ErrHostScopeAlreadySet reports that the job already has a host scope.
	ErrHostScopeAlreadySet = errors.New("host scope already set")
	// ErrProjectScopeAlreadySet reports that the job already has a project scope.
	ErrProjectScopeAlreadySet = errors.New("project scope already set")
	// ErrProjectScopeMissing reports that the job has no project scope yet.
	ErrProjectScopeMissing = errors.New("job has no project scope")
)

// Job holds the runtime state for a single monitored job.
type Job struct {
	mu         sync.Mutex
	logger     *slog.Logger
	identity   jobcontext.JobIdentity
	metadata   jobcontext.JobMetadata
	runnerType string
	state      JobState
	host       *jobscope.JobScopeState
	project    *jobscope.JobScopeState
	evaluation atomic.Pointer[evaluationBundle]
	eventCh    <-chan jobevent.EventRecord
	doneCh     chan struct{}

	startedAt  time.Time
	deadlineAt time.Time
}

type evaluationBundle struct {
	host       *jobscope.JobScopeState
	project    *jobscope.JobScopeState
	evaluation *evaluation.EvaluationState
}

// NewJob creates a running job.
func NewJob(logger *slog.Logger, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string, eventCh <-chan jobevent.EventRecord) *Job {
	now := time.Now().UTC()
	if logger == nil {
		logger = slog.Default()
	}

	job := &Job{
		logger:     logger.With("component", "job", "job_identity", identity),
		identity:   identity,
		metadata:   metadata,
		runnerType: runnerType,
		state:      JobStateRunning,
		eventCh:    eventCh,
		doneCh:     make(chan struct{}),
		startedAt:  now,
		deadlineAt: now.Add(DefaultTTL),
	}
	job.evaluation.Store(&evaluationBundle{})
	if eventCh == nil {
		close(job.doneCh)
		return job
	}
	go job.runEventWorker()
	return job
}

// Identity returns the job's stable CI identity.
func (j *Job) Identity() jobcontext.JobIdentity {
	return j.identity
}

// Metadata returns the job's metadata.
func (j *Job) Metadata() jobcontext.JobMetadata {
	return j.metadata
}

// RunnerType returns the agent-process-wide runner type stamped onto this job.
func (j *Job) RunnerType() string {
	return j.runnerType
}

// StartedAt returns the time the job was created.
func (j *Job) StartedAt() time.Time {
	return j.startedAt
}

// DeadlineAt returns the TTL deadline for the job.
func (j *Job) DeadlineAt() time.Time {
	return j.deadlineAt
}

// State returns the current lifecycle state.
func (j *Job) State() JobState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state
}

// SetHostScope sets the host scope state and updates the evaluation bundle.
// The caller is responsible for resolving scope-local rules before calling it.
func (j *Job) SetHostScope(ctx context.Context, scope *jobscope.JobScopeState) error {
	j.mu.Lock()
	if j.state == JobStateClosing {
		// Finalize races are ignored; the registry already owns the close flow.
		j.mu.Unlock()
		return nil
	}
	if scope == nil {
		j.mu.Unlock()
		return ErrHostScopeRequired
	}
	if scope.Type != jobcontext.ScopeTypeHost {
		j.mu.Unlock()
		return fmt.Errorf("%w: expected %q, got %q", jobscope.ErrScopeTypeMismatch, jobcontext.ScopeTypeHost, scope.Type)
	}
	if j.host != nil {
		j.mu.Unlock()
		return ErrHostScopeAlreadySet
	}
	j.host = scope
	j.setEvaluationBundle()
	j.mu.Unlock()
	j.logger.InfoContext(ctx, "host_scope_set")
	return nil
}

// SetProjectScope sets the project scope state and updates the evaluation bundle.
// The caller is responsible for resolving scope-local rules before calling it.
func (j *Job) SetProjectScope(ctx context.Context, scope *jobscope.JobScopeState) error {
	j.mu.Lock()
	if j.state == JobStateClosing {
		// Finalize races are ignored; the registry already owns the close flow.
		j.mu.Unlock()
		return nil
	}
	if scope == nil {
		j.mu.Unlock()
		return ErrProjectScopeRequired
	}
	if scope.Type != jobcontext.ScopeTypeProject {
		j.mu.Unlock()
		return fmt.Errorf("%w: expected %q, got %q", jobscope.ErrScopeTypeMismatch, jobcontext.ScopeTypeProject, scope.Type)
	}
	if j.project != nil {
		j.mu.Unlock()
		return ErrProjectScopeAlreadySet
	}
	j.project = scope
	j.setEvaluationBundle()
	j.mu.Unlock()
	j.logger.InfoContext(ctx, "project_scope_set")
	return nil
}

// HostScope returns the host scope state, or nil if not set.
func (j *Job) HostScope() *jobscope.JobScopeState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.host
}

// ProjectScope returns the project scope state, or nil if not set.
func (j *Job) ProjectScope() *jobscope.JobScopeState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.project
}

// MarkClosing transitions the job to the closing state. KernelTracker still owns
// the event channel and closes it via the CloseEventChannel effect.
func (j *Job) MarkClosing() {
	j.mu.Lock()
	if j.state == JobStateClosing {
		j.mu.Unlock()
		return
	}
	j.state = JobStateClosing
	j.mu.Unlock()
}

// Done closes after the event worker drains the engine-owned event channel.
func (j *Job) Done() <-chan struct{} {
	return j.doneCh
}

// IsExpired returns true if the job has exceeded its TTL.
func (j *Job) IsExpired() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return time.Now().UTC().After(j.deadlineAt)
}

// setEvaluationBundle installs the event worker's immutable evaluation
// snapshot from the currently attached host/project scopes.
// j.mu must be held.
func (j *Job) setEvaluationBundle() {
	var hostRules *rule.ResolvedRules
	if j.host != nil {
		hostRules = &j.host.ResolvedRules
	}
	var projectRules *rule.ResolvedRules
	if j.project != nil {
		projectRules = &j.project.ResolvedRules
	}

	j.evaluation.Store(&evaluationBundle{
		host:       j.host,
		project:    j.project,
		evaluation: evaluation.NewEvaluationState(hostRules, projectRules),
	})
}

func (j *Job) runEventWorker() {
	defer close(j.doneCh)

	// One activation per worker goroutine, reused across events. Rule
	// evaluation is sequential within a Job (this loop), so a single
	// activation is sufficient and avoids sync.Pool overhead. Parallel
	// evaluation would require either one activation per parallel worker
	// or reintroducing pooling — see EventActivation's concurrency contract.
	activation := celengine.NewEventActivation(celengine.CELInputEvent{})

	for event := range j.eventCh {
		// The worker drains queued events; Job-wide cancellation/finalization
		// is coordinated by JobRegistry through channel close and Done().
		j.processEvent(context.Background(), event, activation)
	}
}

func (j *Job) processEvent(ctx context.Context, event jobevent.EventRecord, activation *celengine.EventActivation) {
	bundle := j.evaluation.Load()
	if bundle.evaluation == nil {
		return
	}

	evaluation.EvaluateEvent(ctx, bundle.evaluation, event, j.identity, j.metadata, j.runnerType, bundle.host, bundle.project, j.logger, activation)
}
