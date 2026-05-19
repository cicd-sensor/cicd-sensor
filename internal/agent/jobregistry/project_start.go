package jobregistry

import (
	"context"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// ApplyGitHubProjectStart registers the GitHub project scope. Hosted jobs can
// start here; self-hosted jobs attach to an existing GitHub host scope.
func (jr *JobRegistry) ApplyGitHubProjectStart(
	ctx context.Context,
	identity jobcontext.JobIdentity,
	metadata jobcontext.JobMetadata,
	runnerKind string,
	peerPID int32,
	projectDefaultMaxAlertsPerRule int,
	projectRuleSources []rulesource.LoadedRules,
	projectManagerConnection managerclient.Connection,
	projectManagerClient ManagerConfigFetcher,
	fetchBaseline bool,
) (*job.Job, error) {
	// Project/start peer authorization lives here because existing-host and
	// hosted project-only flows use different Job/BPF state.
	reservation := jr.reserveJobStart(identity)
	if reservation.existing != nil {
		return jr.attachGitHubProjectScopeToExistingJob(ctx, reservation.existing, identity, metadata, runnerKind, peerPID, projectDefaultMaxAlertsPerRule, projectRuleSources, projectManagerConnection, projectManagerClient, fetchBaseline)
	}
	if reservation.inFlight() {
		return nil, ErrJobAlreadyRegistered
	}
	defer reservation.done()

	return jr.startGitHubProjectOnlyJob(ctx, identity, metadata, runnerKind, peerPID, projectDefaultMaxAlertsPerRule, projectRuleSources, projectManagerConnection, projectManagerClient, fetchBaseline)
}

func (jr *JobRegistry) attachGitHubProjectScopeToExistingJob(
	ctx context.Context,
	existing *job.Job,
	identity jobcontext.JobIdentity,
	metadata jobcontext.JobMetadata,
	runnerKind string,
	peerPID int32,
	projectDefaultMaxAlertsPerRule int,
	projectRuleSources []rulesource.LoadedRules,
	projectManagerConnection managerclient.Connection,
	projectManagerClient ManagerConfigFetcher,
	fetchBaseline bool,
) (*job.Job, error) {
	if existing.ProjectScope() != nil {
		return nil, job.ErrProjectScopeAlreadySet
	}
	if err := jr.verifyPeerPIDBelongsToJob(ctx, peerPID, identity); err != nil {
		return nil, err
	}

	// Self-hosted GitHub builds project scope, then attaches it to the host-created Job.
	var projectScope *jobscope.JobScopeState
	var err error
	if projectManagerClient != nil {
		projectScope, err = jr.buildProjectScopeFromManagerConfig(ctx, identity, metadata, runnerKind, projectManagerConnection, projectManagerClient)
	} else {
		projectScope, err = jr.buildProjectScopeFromLocalConfig(ctx, identity, projectDefaultMaxAlertsPerRule, projectRuleSources, fetchBaseline)
	}
	if err != nil {
		return nil, err
	}
	// SetProjectScope swaps in the host+project evaluation bundle atomically.
	if err := existing.SetProjectScope(ctx, projectScope); err != nil {
		return nil, err
	}
	return existing, nil
}

func (jr *JobRegistry) startGitHubProjectOnlyJob(
	ctx context.Context,
	identity jobcontext.JobIdentity,
	metadata jobcontext.JobMetadata,
	runnerKind string,
	peerPID int32,
	projectDefaultMaxAlertsPerRule int,
	projectRuleSources []rulesource.LoadedRules,
	projectManagerConnection managerclient.Connection,
	projectManagerClient ManagerConfigFetcher,
	fetchBaseline bool,
) (*job.Job, error) {
	var projectScope *jobscope.JobScopeState
	var err error
	if projectManagerClient != nil {
		projectScope, err = jr.buildProjectScopeFromManagerConfig(ctx, identity, metadata, runnerKind, projectManagerConnection, projectManagerClient)
	} else {
		projectScope, err = jr.buildProjectScopeFromLocalConfig(ctx, identity, projectDefaultMaxAlertsPerRule, projectRuleSources, fetchBaseline)
	}
	if err != nil {
		return nil, err
	}

	// Hosted Actions without host/start create the Job runtime here.
	job, err := jr.registerJobRuntime(ctx, identity, metadata, runnerKind)
	if err != nil {
		return nil, err
	}

	// SetProjectScope installs evaluation before the hosted cgroup starts routing.
	if err := job.SetProjectScope(ctx, projectScope); err != nil {
		return nil, err
	}
	if jr.kernelTracker != nil {
		// project_start peer is the root cgroup for hosted project-only jobs.
		if err := jr.bindStartProcessCgroupToJob(ctx, identity, peerPID, "github_project_start"); err != nil {
			return nil, err
		}
	}
	return job, nil
}

// buildProjectScopeFromManagerConfig builds a resolved project scope from manager config.
func (jr *JobRegistry) buildProjectScopeFromManagerConfig(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerKind string, projectManagerConnection managerclient.Connection, projectManagerClient ManagerConfigFetcher) (*jobscope.JobScopeState, error) {
	projectScope := jobscope.NewProject()
	managerConfig, err := jr.fetchManagerConfig(ctx, identity, metadata, runnerKind, projectManagerClient, "project_manager_config_fetched")
	if err != nil {
		return nil, err
	}
	if err := projectScope.ApplyManagerConfig(managerConfig); err != nil {
		return nil, err
	}
	jr.startManagerJobLogs(projectScope, identity, projectManagerConnection)
	projectScope.ResolveRules(identity)
	return projectScope, nil
}

// buildProjectScopeFromLocalConfig builds a resolved project scope from project-local config.
func (jr *JobRegistry) buildProjectScopeFromLocalConfig(ctx context.Context, identity jobcontext.JobIdentity, projectDefaultMaxAlertsPerRule int, projectRuleSources []rulesource.LoadedRules, fetchBaseline bool) (*jobscope.JobScopeState, error) {
	projectScope := jobscope.NewProject()
	if fetchBaseline {
		baselineSource, err := jr.loadBaselineRules(ctx, identity)
		if err != nil {
			return nil, err
		}
		if err := projectScope.ApplyBaselineRules(baselineSource); err != nil {
			return nil, err
		}
	}
	if err := projectScope.ApplyProjectLocalConfig(jobscope.ProjectLocalConfig{
		RuleSources:             projectRuleSources,
		DefaultMaxAlertsPerRule: projectDefaultMaxAlertsPerRule,
	}); err != nil {
		return nil, err
	}
	projectScope.ResolveRules(identity)
	return projectScope, nil
}
