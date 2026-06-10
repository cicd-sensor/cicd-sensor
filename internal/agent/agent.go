package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/listener"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
)

// Agent wires the host listener, job registry, and kernel tracker.
type Agent struct {
	logger                    *slog.Logger
	hostManagerConn           managerclient.Connection
	hostManagerClient         *managerclient.ConfigClient
	provider                  jobcontext.Provider
	runnerType                string
	jobRegistry               *jobregistry.JobRegistry
	kernelTracker             *kerneltracker.KernelTracker
	socketPath                string
	githubK8sRunnerSocketPath string
	shutdownGrace             time.Duration
	reaperCancel              context.CancelFunc
	cancelEngine              context.CancelFunc
	engineDone                <-chan error
}

const defaultAgentShutdownGrace = 8 * time.Second

// NewAgent creates an agent for one provider and one control socket.
// runnerType is copied into every Job for logs/reports.
func NewAgent(logger *slog.Logger, socketPath string, provider jobcontext.Provider, runnerType string, hostManagerConn managerclient.Connection, hostManagerClient *managerclient.ConfigClient) *Agent {
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{
		logger:            logger.With("component", "agent"),
		hostManagerConn:   hostManagerConn,
		hostManagerClient: hostManagerClient,
		provider:          provider,
		runnerType:        runnerType,
		socketPath:        socketPath,
	}
}

// SetShutdownGrace overrides the default best-effort drain window used when
// the agent is asked to stop.
func (a *Agent) SetShutdownGrace(grace time.Duration) {
	if grace > 0 {
		a.shutdownGrace = grace
	}
}

// SetGitHubK8sRunnerSocketPath enables the GitHub Kubernetes runner socket.
func (a *Agent) SetGitHubK8sRunnerSocketPath(path string) {
	a.githubK8sRunnerSocketPath = path
}

// Run starts the listener and TTL finalizer, then blocks until ctx is canceled.
// On shutdown it finalizes all remaining jobs.
func (a *Agent) Run(ctx context.Context) error {
	// Build subsystems. JobRegistry is first so KernelTracker can observe it.
	var hostManagerClient jobregistry.ManagerConfigFetcher
	if a.hostManagerClient != nil {
		hostManagerClient = a.hostManagerClient
		if a.runnerType == "kubernetes" {
			cacheReq, err := hostConfigCacheRequest(a.provider, a.runnerType)
			if err != nil {
				return err
			}
			cache, err := managerclient.NewHostConfigCache(a.logger, a.hostManagerClient, cacheReq, managerclient.DefaultHostConfigCacheRefreshInterval)
			if err != nil {
				return fmt.Errorf("new host config cache: %w", err)
			}
			if err := cache.Prime(ctx); err != nil {
				return err
			}
			go cache.Run(ctx)
			hostManagerClient = cache
		}
	}
	jobRegistry := jobregistry.New(a.logger)

	kernelTracker, err := kerneltracker.New(a.logger, jobRegistry)
	if err != nil {
		return fmt.Errorf("new kernel tracker: %w", err)
	}
	jobRegistry.BindKernelTracker(kernelTracker)

	l := listener.New(listener.Config{
		Logger:                a.logger,
		JobRegistry:           jobRegistry,
		SocketPath:            a.socketPath,
		HostManagerConnection: a.hostManagerConn,
		HostManagerClient:     hostManagerClient,
		RunnerType:            a.runnerType,
		Provider:              a.provider,
	})
	listeners := []*listener.Listener{l}
	if a.provider == jobcontext.ProviderGitHub && a.runnerType == "kubernetes" && a.githubK8sRunnerSocketPath != "" {
		listeners = append(listeners, listener.NewGitHubK8sStart(listener.Config{
			Logger:                a.logger,
			JobRegistry:           jobRegistry,
			SocketPath:            a.githubK8sRunnerSocketPath,
			HostManagerConnection: a.hostManagerConn,
			HostManagerClient:     hostManagerClient,
		}))
	}

	// Expose subsystems used by shutdown.
	a.kernelTracker = kernelTracker
	a.jobRegistry = jobRegistry

	// Run KernelTracker on its own context so shutdown can drain it after ctx cancels.
	engineCtx, cancelEngine := context.WithCancel(context.Background())
	a.cancelEngine = cancelEngine

	engineDone := make(chan error, 1)
	a.engineDone = engineDone
	go func() {
		engineDone <- kernelTracker.Run(engineCtx)
	}()

	a.logger.InfoContext(ctx, "agent_started",
		"socket", a.socketPath,
		"github_k8s_runner_socket", a.githubK8sRunnerSocketPath,
	)

	// Launch the TTL finalizer.
	a.startExpiredJobFinalizer(ctx)

	// Serve HTTP; blocks until ctx is canceled or one listener errors.
	err = serveListeners(ctx, listeners)

	// Tear down subsystems in reverse order: FinalizeAll, KernelTracker close, engine cancel.
	a.logger.InfoContext(ctx, "agent_stopping")
	a.shutdown(ctx)

	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	return nil
}

func hostConfigCacheRequest(provider jobcontext.Provider, runnerType string) (*managerv1beta1.FetchConfigRequest, error) {
	identity, err := hostConfigCacheIdentity(provider)
	if err != nil {
		return nil, err
	}
	return &managerv1beta1.FetchConfigRequest{
		RunnerType:  runnerType,
		JobIdentity: protoconv.ToProtoJobIdentity(identity),
	}, nil
}

func hostConfigCacheIdentity(provider jobcontext.Provider) (jobcontext.JobIdentity, error) {
	// FetchConfig currently requires a syntactically valid JobIdentity even
	// though the Kubernetes host config is node-owned and reused for all jobs.
	// Real job identity is still used when each Job resolves rules and emits logs.
	switch provider {
	case jobcontext.ProviderGitHub:
		return jobcontext.GitHubJobIdentity("github.com", "cicd-sensor/host-config", "1", "host-config", "1", "host-config"), nil
	case jobcontext.ProviderGitLab:
		return jobcontext.GitLabJobIdentity("gitlab.com", "cicd-sensor/host-config", "1"), nil
	default:
		return jobcontext.JobIdentity{}, fmt.Errorf("unsupported provider for host config cache: %s", provider)
	}
}

func serveListeners(ctx context.Context, listeners []*listener.Listener) error {
	if len(listeners) == 1 {
		return listeners[0].Serve(ctx)
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, len(listeners))
	for _, l := range listeners {
		go func() {
			errCh <- l.Serve(serveCtx)
		}()
	}

	err := <-errCh
	cancel()
	for range len(listeners) - 1 {
		if nextErr := <-errCh; err == nil {
			err = nextErr
		}
	}
	return err
}

// startExpiredJobFinalizer periodically finalizes jobs that exceeded their TTL.
func (a *Agent) startExpiredJobFinalizer(ctx context.Context) {
	reaperCtx, cancel := context.WithCancel(ctx)
	a.reaperCancel = cancel
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-reaperCtx.Done():
				return
			case <-ticker.C:
				a.jobRegistry.FinalizeExpiredJobs(reaperCtx)
			}
		}
	}()
}

// shutdown finalizes all jobs and tears down subsystems.
func (a *Agent) shutdown(ctx context.Context) {
	shutdownGrace := a.shutdownGrace
	if shutdownGrace <= 0 {
		shutdownGrace = defaultAgentShutdownGrace
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancelShutdown()

	// Stop the TTL finalizer so it cannot touch jobs while we drain.
	if a.reaperCancel != nil {
		a.reaperCancel()
	}

	// Finalize active jobs while the KernelTracker loop and kernel IO are still alive.
	finalizedJobs := 0
	if a.jobRegistry != nil {
		finalizedJobs = len(a.jobRegistry.All())
		a.jobRegistry.FinalizeAll(shutdownCtx, kerneltracker.EndShutdown)
	}

	// Close KernelTracker's producer so no new events reach the loop.
	if a.kernelTracker != nil {
		if err := a.kernelTracker.Close(); err != nil {
			a.logger.WarnContext(ctx, "agent_runtime_close_failed", "error", err)
		}
	}

	// Cancel the KernelTracker loop and wait for it to drain.
	if a.cancelEngine != nil {
		a.cancelEngine()
	}
	if a.engineDone != nil {
		if err := <-a.engineDone; err != nil {
			a.logger.WarnContext(ctx, "agent_engine_stopped_with_error", "error", err)
		}
	}

	a.logger.InfoContext(ctx, "agent_stopped", "finalized_jobs", finalizedJobs)
}
