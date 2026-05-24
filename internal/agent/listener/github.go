package listener

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// handleGitHubHostStart creates the host scope and seeds cgroup tracking for
// self-hosted GitHub runners.
func (l *Listener) handleGitHubHostStart(w http.ResponseWriter, r *http.Request) {
	var req githubHostStartRequest
	if err := l.decodeJSONBody(w, r, &req); err != nil {
		l.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	identity := req.JobIdentity
	if identity.Provider != jobcontext.ProviderGitHub {
		l.writeError(w, r, http.StatusBadRequest, "provider must be github")
		return
	}
	if err := identity.Validate(); err != nil {
		l.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	metadata := req.Metadata
	rootPID, err := requestPeerPID(r.Context())
	if err != nil {
		l.logger.WarnContext(r.Context(), "peer_pid_unavailable", "error", err)
		l.writeError(w, r, http.StatusBadRequest, "peer pid unavailable")
		return
	}

	_, err = l.jobRegistry.ApplyGitHubHostStart(r.Context(), identity, metadata, l.runnerType, rootPID, l.hostManagerConn, l.hostManagerClient)
	if err != nil {
		l.writeStartError(w, r, "host_start_failed", err)
		return
	}

	l.logger.InfoContext(r.Context(), "host_start_accepted", "job_identity", identity)
	l.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"job_identity": identity,
		"status":       "ok",
	})
}

// handleGitHubProjectStart attaches project rules to an existing host Job, or
// creates a project-only Job for hosted runners.
func (l *Listener) handleGitHubProjectStart(w http.ResponseWriter, r *http.Request) {
	var req githubProjectStartRequest
	if err := l.decodeJSONBody(w, r, &req); err != nil {
		l.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	identity := req.JobIdentity
	if identity.Provider != jobcontext.ProviderGitHub {
		l.writeError(w, r, http.StatusBadRequest, "provider must be github")
		return
	}
	if err := req.Validate(); err != nil {
		l.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if err := identity.Validate(); err != nil {
		l.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	metadata := req.Metadata
	peerPID, err := requestPeerPID(r.Context())
	if err != nil {
		l.logger.WarnContext(r.Context(), "peer_pid_unavailable", "error", err)
		l.writeError(w, r, http.StatusBadRequest, "peer pid unavailable")
		return
	}

	// Registry owns peer authorization because it depends on Job/BPF state.
	managerConnection := managerclient.Connection{BaseURL: req.ManagerURL, Token: req.ManagerToken}
	var projectManagerClient jobregistry.ManagerConfigFetcher
	if req.ManagerURL != "" {
		projectManagerClient, err = managerclient.NewConfigClient(l.logger, managerConnection)
		if err != nil {
			l.writeStartError(w, r, "project_start_failed", err)
			return
		}
	}

	_, err = l.jobRegistry.ApplyGitHubProjectStart(
		r.Context(),
		identity,
		metadata,
		l.runnerType,
		peerPID,
		req.DefaultMaxAlertsPerRule,
		req.RuleSources,
		managerConnection,
		projectManagerClient,
		req.DebugEnabled,
	)
	if err != nil {
		if errors.Is(err, jobregistry.ErrPeerNotInJob) {
			l.writeError(w, r, http.StatusForbidden, "peer not in job tracking set")
			return
		}
		l.writeStartError(w, r, "project_start_failed", err)
		return
	}

	l.logger.InfoContext(r.Context(), "project_start_accepted", "job_identity", identity)
	l.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"job_identity": identity,
		"status":       "ok",
	})
}

// handleGitHubJobHealth is a read-only lifecycle probe for hooks and final
// workflow steps.
func (l *Listener) handleGitHubJobHealth(w http.ResponseWriter, r *http.Request) {
	identity, ok := l.decodeGitHubJobIdentity(w, r)
	if !ok {
		return
	}
	peerPID, err := requestPeerPID(r.Context())
	if err != nil {
		l.logger.WarnContext(r.Context(), "peer_pid_unavailable", "error", err)
		l.writeError(w, r, http.StatusBadRequest, "peer pid unavailable")
		return
	}
	health, err := l.jobRegistry.GetGitHubJobHealth(r.Context(), identity, peerPID)
	if err != nil {
		switch {
		case errors.Is(err, jobregistry.ErrJobNotFound):
			l.writeError(w, r, http.StatusNotFound, "job not found")
		case errors.Is(err, jobregistry.ErrPeerNotInJob):
			l.writeError(w, r, http.StatusForbidden, "peer not in job tracking set")
		default:
			l.logger.ErrorContext(r.Context(), "job_health_failed", "job_identity", identity, "error", err)
			l.writeError(w, r, http.StatusInternalServerError, "internal error")
		}
		return
	}

	l.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"job_identity": health.Identity,
		"host":         map[string]string{"status": scopeHealthStatus(health.HostActive)},
		"project":      map[string]string{"status": scopeHealthStatus(health.ProjectActive)},
		"status":       "ok",
	})
}

// handleGitHubHostEnd lets the GitHub completed hook finalize host-scoped Jobs
// whose runner cgroup may outlive the workflow.
func (l *Listener) handleGitHubHostEnd(w http.ResponseWriter, r *http.Request) {
	identity, ok := l.decodeGitHubJobIdentity(w, r)
	if !ok {
		return
	}
	peerPID, err := requestPeerPID(r.Context())
	if err != nil {
		l.logger.WarnContext(r.Context(), "peer_pid_unavailable", "error", err)
		l.writeError(w, r, http.StatusBadRequest, "peer pid unavailable")
		return
	}
	if err := l.jobRegistry.RequestGitHubHostEnd(r.Context(), identity, peerPID); err != nil {
		switch {
		case errors.Is(err, jobregistry.ErrHostScopeMissing):
			l.writeError(w, r, http.StatusConflict, "job has no host scope")
		case errors.Is(err, jobregistry.ErrPeerNotInJob):
			l.writeError(w, r, http.StatusForbidden, "peer not in job tracking set")
		default:
			l.logger.ErrorContext(r.Context(), "host_end_failed", "job_identity", identity, "error", err)
			l.writeError(w, r, http.StatusInternalServerError, "internal error")
		}
		return
	}

	l.logger.InfoContext(r.Context(), "host_end_accepted", "job_identity", identity)
	l.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"job_identity": identity,
		"status":       "ok",
	})
}

// handleGitHubProjectResult returns a report document snapshot; it does not
// finalize the Job.
func (l *Listener) handleGitHubProjectResult(w http.ResponseWriter, r *http.Request) {
	identity, ok := l.decodeGitHubJobIdentity(w, r)
	if !ok {
		return
	}
	peerPID, err := requestPeerPID(r.Context())
	if err != nil {
		l.logger.WarnContext(r.Context(), "peer_pid_unavailable", "error", err)
		l.writeError(w, r, http.StatusBadRequest, "peer pid unavailable")
		return
	}
	body, err := l.jobRegistry.RequestGitHubProjectResult(r.Context(), identity, peerPID)
	if err != nil {
		switch {
		case errors.Is(err, jobregistry.ErrJobNotFound):
			l.writeError(w, r, http.StatusNotFound, "job not found")
		case errors.Is(err, jobregistry.ErrPeerNotInJob):
			l.writeError(w, r, http.StatusForbidden, "peer not in job tracking set")
		case errors.Is(err, job.ErrProjectScopeMissing):
			l.writeError(w, r, http.StatusConflict, "job has no project scope")
		default:
			l.logger.ErrorContext(r.Context(), "project_result_failed", "error", err)
			l.writeError(w, r, http.StatusInternalServerError, "internal error")
		}
		return
	}

	if len(body) > projectResultMaxBytes {
		l.logger.WarnContext(r.Context(), "project_result_too_large",
			"size_bytes", len(body),
			"limit_bytes", projectResultMaxBytes,
		)
		l.writeError(w, r, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("summary_log exceeds %d-byte limit", projectResultMaxBytes))
		return
	}

	// The agent returns the report document bytes; rendering belongs to ctl.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		l.logger.WarnContext(r.Context(), "project_result_write_failed", "error", err)
	}
}

// handleGitHubStagingPut records proxy-discovered containers after resolving
// their peer PID back to a tracked Job.
func (l *Listener) handleGitHubStagingPut(w http.ResponseWriter, r *http.Request) {
	if !l.requireRequestPeerUIDMatchesAgentOwner(w, r) {
		return
	}

	var req jobcontext.GitHubStagingPutRequest
	if err := l.decodeJSONBody(w, r, &req); err != nil {
		l.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Basename == "" {
		l.writeError(w, r, http.StatusBadRequest, "basename is required")
		return
	}

	// GitHub staging resolves identity from the peer cgroup; misses are
	// normal because unrelated host containers also pass through the proxy.
	identity, found, err := l.jobRegistry.FindJobForPeerPID(r.Context(), req.PeerPID)
	if err != nil {
		l.logger.ErrorContext(r.Context(), "github_staging_put_failed", "error", err)
		l.writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}
	status := "ignored"
	if found {
		if err := l.jobRegistry.StageCgroupBasenameForJob(r.Context(), req.Basename, identity); err != nil {
			// The Job can finish between cgroup lookup and staging insert.
			if !errors.Is(err, jobregistry.ErrJobNotFound) {
				l.logger.ErrorContext(r.Context(), "github_staging_put_failed", "error", err)
				l.writeError(w, r, http.StatusInternalServerError, "internal error")
				return
			}
		} else {
			status = "staged"
		}
	}
	l.logger.InfoContext(r.Context(), "github_staging_put",
		"basename", req.Basename,
		"peer_pid", req.PeerPID,
		"status", status,
	)
	l.writeJSON(r.Context(), w, http.StatusOK, map[string]string{"status": status})
}

// decodeGitHubJobIdentity keeps identity-only GitHub routes on the same
// validation path.
func (l *Listener) decodeGitHubJobIdentity(w http.ResponseWriter, r *http.Request) (jobcontext.JobIdentity, bool) {
	var req githubJobIdentityRequest
	if err := l.decodeJSONBody(w, r, &req); err != nil {
		l.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return jobcontext.JobIdentity{}, false
	}
	identity := req.JobIdentity
	if identity.Provider != jobcontext.ProviderGitHub {
		l.writeError(w, r, http.StatusBadRequest, "provider must be github")
		return jobcontext.JobIdentity{}, false
	}
	if err := identity.Validate(); err != nil {
		l.writeError(w, r, http.StatusBadRequest, err.Error())
		return jobcontext.JobIdentity{}, false
	}
	return identity, true
}

func scopeHealthStatus(active bool) string {
	if active {
		return "active"
	}
	return "missing"
}
