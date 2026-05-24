// Package jobregistry owns the active job map and start/finalize orchestration.
// Per-job runtime state lives in job; per-scope state lives in jobscope.
package jobregistry

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/joblogs"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/baseline"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// ErrJobNotFound reports that no job is registered for the given identity.
var ErrJobNotFound = errors.New("job not found")

// ErrHostAfterProject reports that host/start arrived after a project-only job
// had already been created.
var ErrHostAfterProject = errors.New("host start must happen before project start")

// ErrHostScopeMissing reports that a host lifecycle operation targeted a Job
// that was created without host/start.
var ErrHostScopeMissing = errors.New("host scope missing")

// ErrHostManagerRequired reports that host scope configuration cannot be built
// because the agent was started without a manager connection.
var ErrHostManagerRequired = errors.New("host manager is required")

// ErrJobAlreadyRegistered reports that the job identity is already active.
var ErrJobAlreadyRegistered = errors.New("job already registered")

// ErrPeerNotInJob reports that a project-scope request targeting an existing
// host-linked Job came from a peer process whose cgroup is not in that
// Job's tracking set. The listener maps this to 403 Forbidden.
var ErrPeerNotInJob = errors.New("peer pid not in job tracking set")

type ManagerConfigFetcher interface {
	FetchConfig(ctx context.Context, req *managerv1.FetchConfigRequest) (*managerclient.FetchResult, error)
}

type BaselineLoader func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error)

// JobRegistry is the registry of all active jobs.
type JobRegistry struct {
	mu     sync.Mutex
	logger *slog.Logger
	// jobLogger is intentionally component-free; job.NewJob stamps component=job.
	jobLogger     *slog.Logger
	kernelTracker *kerneltracker.KernelTracker
	jobs          map[jobcontext.JobIdentity]*job.Job
	baselineLoad  BaselineLoader
	// starting hides half-created jobs and serializes duplicate start requests.
	starting map[jobcontext.JobIdentity]chan struct{}
}

// New creates an empty job registry. Callers must follow with BindKernelTracker
// before starting jobs that rely on cgroup tracking.
func New(logger *slog.Logger) *JobRegistry {
	if logger == nil {
		logger = slog.Default()
	}
	return &JobRegistry{
		logger:       logger.With("component", "job_registry"),
		jobLogger:    logger,
		jobs:         make(map[jobcontext.JobIdentity]*job.Job),
		baselineLoad: baseline.LoadForProvider,
		starting:     make(map[jobcontext.JobIdentity]chan struct{}),
	}
}

func (jr *JobRegistry) SetBaselineLoadForTesting(load BaselineLoader) {
	jr.baselineLoad = load
}

// BindKernelTracker completes startup wiring after the KernelTracker is built.
func (jr *JobRegistry) BindKernelTracker(kernelTracker *kerneltracker.KernelTracker) {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	jr.kernelTracker = kernelTracker
}

type jobStartReservation struct {
	existing *job.Job
	waitFor  <-chan struct{}
	release  func()
}

func (r jobStartReservation) inFlight() bool {
	return r.waitFor != nil
}

func (r jobStartReservation) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.waitFor:
		return nil
	}
}

func (r jobStartReservation) done() {
	if r.release != nil {
		r.release()
	}
}

// reserveJobStart reserves one identity creation flow. Staging sees
// ErrJobNotFound instead of a half-attached Job while the reservation exists.
func (jr *JobRegistry) reserveJobStart(identity jobcontext.JobIdentity) jobStartReservation {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	if existing := jr.jobs[identity]; existing != nil {
		return jobStartReservation{existing: existing}
	}
	if starting, ok := jr.starting[identity]; ok {
		return jobStartReservation{waitFor: starting}
	}
	starting := make(chan struct{})
	jr.starting[identity] = starting
	release := func() {
		jr.mu.Lock()
		defer jr.mu.Unlock()
		delete(jr.starting, identity)
		close(starting)
	}
	return jobStartReservation{release: release}
}

func (jr *JobRegistry) waitForJobStartReservation(ctx context.Context, identity jobcontext.JobIdentity) (jobStartReservation, error) {
	for {
		reservation := jr.reserveJobStart(identity)
		if !reservation.inFlight() {
			return reservation, nil
		}
		if err := reservation.wait(ctx); err != nil {
			return jobStartReservation{}, err
		}
	}
}

// registerJobRuntime creates a running Job, wires BPF events, and stores it.
// Cgroup binding is provider-specific and happens in the start flow.
func (jr *JobRegistry) registerJobRuntime(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string) (*job.Job, error) {
	jr.mu.Lock()
	if _, ok := jr.jobs[identity]; ok {
		jr.mu.Unlock()
		return nil, ErrJobAlreadyRegistered
	}
	kernelTracker := jr.kernelTracker
	jobLogger := jr.jobLogger
	if jobLogger == nil {
		jobLogger = jr.logger
	}
	jr.mu.Unlock()

	var eventCh <-chan jobevent.EventRecord
	engineRegistered := false
	if kernelTracker != nil {
		registeredEventCh, err := kernelTracker.RegisterJob(ctx, identity)
		if err != nil {
			return nil, err
		}
		eventCh = registeredEventCh
		engineRegistered = true
	}

	j := job.NewJob(jobLogger, identity, metadata, runnerType, eventCh)
	jr.mu.Lock()
	if _, ok := jr.jobs[identity]; ok {
		jr.mu.Unlock()
		if engineRegistered {
			_ = kernelTracker.RemoveJob(context.Background(), identity)
		}
		return nil, ErrJobAlreadyRegistered
	}
	jr.jobs[identity] = j
	jr.mu.Unlock()

	jr.logger.InfoContext(ctx, "job_registered",
		"job_identity", identity,
	)
	return j, nil
}

func (jr *JobRegistry) get(identity jobcontext.JobIdentity) *job.Job {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	return jr.jobs[identity]
}

// All returns a snapshot of all current jobs.
func (jr *JobRegistry) All() []*job.Job {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	out := make([]*job.Job, 0, len(jr.jobs))
	for _, j := range jr.jobs {
		out = append(out, j)
	}
	return out
}

func countRuleSets(sources []rulesource.LoadedRules) int {
	var n int
	for _, source := range sources {
		n += len(source.RuleSets)
	}
	return n
}

func countRuleModifiers(sources []rulesource.LoadedRules) int {
	var n int
	for _, source := range sources {
		n += len(source.RuleModifiers)
	}
	return n
}

func managerConfigFromFetchResult(result *managerclient.FetchResult) jobscope.ManagerConfig {
	if result == nil {
		return jobscope.ManagerConfig{}
	}
	return jobscope.ManagerConfig{
		RuleSources:             result.RuleSources,
		ConfigRevision:          result.ConfigRevision,
		OutputSettings:          result.OutputSettings,
		DefaultMaxAlertsPerRule: result.DefaultMaxAlertsPerRule,
	}
}

func (jr *JobRegistry) startManagerJobLogs(scope *jobscope.JobScopeState, identity jobcontext.JobIdentity, conn managerclient.Connection) {
	if scope == nil || scope.OutputSettings == nil {
		return
	}
	logs := joblogs.NewManagerJobLogs(joblogs.ManagerJobLogsConfig{
		Logger:         jr.logger,
		Connection:     conn,
		Identity:       identity,
		Type:           scope.Type,
		OutputSettings: scope.OutputSettings,
	})
	scope.SetManagerJobLogs(logs)
}
