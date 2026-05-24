package jobregistry

import (
	"context"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// ApplyGitHubHostStart starts a host scope and seeds tracking from the caller cgroup.
func (jr *JobRegistry) ApplyGitHubHostStart(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string, rootPID int32, hostManagerConnection managerclient.Connection, hostManagerClient ManagerConfigFetcher) (*job.Job, error) {
	// Build scope config first, register the Job runtime, attach the scope, then
	// bind the caller cgroup so routed events always see a resolved scope.
	reservation := jr.reserveJobStart(identity)
	if reservation.existing != nil {
		if reservation.existing.HostScope() == nil && reservation.existing.ProjectScope() != nil {
			return nil, ErrHostAfterProject
		}
		return nil, ErrJobAlreadyRegistered
	}
	if reservation.inFlight() {
		return nil, ErrJobAlreadyRegistered
	}
	defer reservation.done()

	if hostManagerClient == nil {
		return nil, ErrHostManagerRequired
	}
	hostScope, err := jr.buildHostScopeFromManagerConfig(ctx, identity, metadata, runnerType, hostManagerConnection, hostManagerClient)
	if err != nil {
		return nil, err
	}

	// Register the runtime before attaching scope so the Job owns its event worker.
	job, err := jr.registerJobRuntime(ctx, identity, metadata, runnerType)
	if err != nil {
		return nil, err
	}

	// SetHostScope installs the evaluation bundle; bind only after rules are live.
	if err := job.SetHostScope(ctx, hostScope); err != nil {
		return nil, err
	}

	if jr.kernelTracker != nil {
		// GitHub host start can seed tracking immediately from the caller cgroup.
		if err := jr.bindStartProcessCgroupToJob(ctx, identity, rootPID, "github_host_start"); err != nil {
			return nil, err
		}
	}
	return job, nil
}

// ApplyGitLabHostStart lazily creates the GitLab host scope from docker proxy labels.
func (jr *JobRegistry) ApplyGitLabHostStart(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string, hostManagerConnection managerclient.Connection, hostManagerClient ManagerConfigFetcher) (*job.Job, error) {
	// Docker proxy calls can race; wait for any in-flight lazy create, then
	// build and attach the host scope. Cgroup tracking starts later via staging.
	reservation, err := jr.waitForJobStartReservation(ctx, identity)
	if err != nil {
		return nil, err
	}
	if reservation.existing != nil {
		return reservation.existing, nil
	}
	defer reservation.done()

	if hostManagerClient == nil {
		return nil, ErrHostManagerRequired
	}
	hostScope, err := jr.buildHostScopeFromManagerConfig(ctx, identity, metadata, runnerType, hostManagerConnection, hostManagerClient)
	if err != nil {
		return nil, err
	}

	// Register now; GitLab seeds tracking later through staging_map promotion.
	job, err := jr.registerJobRuntime(ctx, identity, metadata, runnerType)
	if err != nil {
		return nil, err
	}
	// SetHostScope installs the evaluation bundle before staged cgroups can route.
	if err := job.SetHostScope(ctx, hostScope); err != nil {
		return nil, err
	}
	return job, nil
}

// buildHostScopeFromManagerConfig builds a resolved host scope from manager config.
func (jr *JobRegistry) buildHostScopeFromManagerConfig(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string, hostManagerConnection managerclient.Connection, hostManagerClient ManagerConfigFetcher) (*jobscope.JobScopeState, error) {
	hostScope := jobscope.NewHost()
	managerConfig, err := jr.fetchManagerConfig(ctx, identity, metadata, runnerType, hostManagerClient, "manager_config_fetched")
	if err != nil {
		return nil, err
	}
	if err := hostScope.ApplyManagerConfig(managerConfig); err != nil {
		return nil, err
	}
	jr.startManagerJobLogs(hostScope, identity, hostManagerConnection)
	hostScope.ResolveRules(identity)
	return hostScope, nil
}

func (jr *JobRegistry) fetchManagerConfig(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string, managerClient ManagerConfigFetcher, eventName string) (jobscope.ManagerConfig, error) {
	result, err := managerClient.FetchConfig(ctx, &managerv1.FetchConfigRequest{
		RunnerType:  runnerType,
		JobIdentity: protoconv.ToProtoJobIdentity(identity),
	})
	if err != nil {
		return jobscope.ManagerConfig{}, fmt.Errorf("manager config fetch: %w", err)
	}
	jr.logger.InfoContext(ctx, eventName,
		"job_identity", identity,
		"config_revision", result.ConfigRevision,
		"rule_sets", countRuleSets(result.RuleSources),
		"rule_modifiers", countRuleModifiers(result.RuleSources),
	)
	return managerConfigFromFetchResult(result), nil
}

func (jr *JobRegistry) loadBaselineRules(ctx context.Context, identity jobcontext.JobIdentity) (rulesource.LoadedRules, error) {
	baselineSource, err := jr.baselineLoad(ctx, jr.logger, string(identity.Provider))
	if err != nil {
		return rulesource.LoadedRules{}, fmt.Errorf("baseline fetch: %w", err)
	}
	jr.logger.InfoContext(ctx, "baseline_rules_fetched",
		"job_identity", identity,
		"rule_sets", len(baselineSource.RuleSets),
		"rule_modifiers", len(baselineSource.RuleModifiers),
	)
	return baselineSource, nil
}
