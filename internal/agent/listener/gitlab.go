package listener

import (
	"errors"
	"net/http"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// handleGitLabHostStart lazily creates the host Job from the trusted Docker
// proxy path.
func (l *Listener) handleGitLabHostStart(w http.ResponseWriter, r *http.Request) {
	if !l.requireRequestPeerUIDMatchesAgentOwner(w, r) {
		return
	}

	var req jobcontext.GitLabHostStartRequest
	if err := l.decodeJSONBody(w, r, &req); err != nil {
		l.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	identity := req.JobIdentity
	if identity.Provider != jobcontext.ProviderGitLab {
		l.writeError(w, r, http.StatusBadRequest, "provider must be gitlab")
		return
	}
	if err := identity.Validate(); err != nil {
		l.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	metadata := req.Metadata

	if _, err := l.jobRegistry.ApplyGitLabHostStart(r.Context(), identity, metadata, l.runnerType, l.hostManagerConn, l.hostManagerClient); err != nil {
		l.writeStartError(w, r, "gitlab_host_start_failed", err)
		return
	}

	l.logger.InfoContext(r.Context(), "gitlab_host_start_accepted",
		"job_identity", identity,
	)
	l.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"job_identity": identity,
		"status":       "ok",
	})
}

// handleGitLabStagingPut stages Docker proxy-discovered containers. The proxy
// can identify an existing Job by peer PID; if peer lookup misses but trusted
// GitLab runner labels are present, this handler creates the host Job and
// stages the cgroup basename in the same request.
func (l *Listener) handleGitLabStagingPut(w http.ResponseWriter, r *http.Request) {
	if !l.requireRequestPeerUIDMatchesAgentOwner(w, r) {
		return
	}

	var req jobcontext.GitLabStagingPutRequest
	if err := l.decodeJSONBody(w, r, &req); err != nil {
		l.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Basename == "" {
		l.writeError(w, r, http.StatusBadRequest, "basename is required")
		return
	}

	identity, found, err := l.jobRegistry.FindJobForPeerPID(r.Context(), req.PeerPID)
	if err != nil {
		l.logger.ErrorContext(r.Context(), "gitlab_staging_put_failed", "error", err)
		l.writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}
	if found {
		status := "ignored"
		if err := l.jobRegistry.StageCgroupBasenameForJob(r.Context(), req.Basename, identity); err != nil {
			// The Job can finish between cgroup lookup and staging insert.
			if !errors.Is(err, jobregistry.ErrJobNotFound) {
				l.logger.ErrorContext(r.Context(), "gitlab_staging_put_failed", "error", err)
				l.writeError(w, r, http.StatusInternalServerError, "internal error")
				return
			}
		} else {
			status = "staged"
		}
		l.logger.InfoContext(r.Context(), "gitlab_staging_put",
			"basename", req.Basename,
			"peer_pid", req.PeerPID,
			"job_identity", identity,
			"status", status,
		)
		l.writeJSON(r.Context(), w, http.StatusOK, map[string]string{"status": status})
		return
	}

	if req.JobIdentity == nil {
		l.logger.InfoContext(r.Context(), "gitlab_staging_put",
			"basename", req.Basename,
			"peer_pid", req.PeerPID,
			"status", "ignored",
		)
		l.writeJSON(r.Context(), w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}

	labelsIdentity := *req.JobIdentity
	if labelsIdentity.Provider != jobcontext.ProviderGitLab {
		l.writeError(w, r, http.StatusBadRequest, "job_identity.provider must be gitlab")
		return
	}
	if err := labelsIdentity.Validate(); err != nil {
		l.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	status, ok := l.stageGitLabBasename(w, r, req.Basename, labelsIdentity, req.Metadata)
	if !ok {
		return
	}

	l.logger.InfoContext(r.Context(), "gitlab_staging_put",
		"basename", req.Basename,
		"peer_pid", req.PeerPID,
		"job_identity", labelsIdentity,
		"status", status,
	)
	l.writeJSON(r.Context(), w, http.StatusOK, map[string]string{"status": status})
}

// handleGitLabK8sStagingPut records NRI-discovered Kubernetes containers.
// NRI runs in containerd's callback path, so this local handler owns lazy Job
// creation and must not force NRI through an extra host/start round trip.
func (l *Listener) handleGitLabK8sStagingPut(w http.ResponseWriter, r *http.Request) {
	if !l.requireRequestPeerUIDMatchesAgentOwner(w, r) {
		return
	}

	var req jobcontext.GitLabK8sStagingPutRequest
	if err := l.decodeJSONBody(w, r, &req); err != nil {
		l.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Basename == "" {
		l.writeError(w, r, http.StatusBadRequest, "basename is required")
		return
	}
	identity := req.JobIdentity
	if identity.Provider != jobcontext.ProviderGitLab {
		l.writeError(w, r, http.StatusBadRequest, "job_identity.provider must be gitlab")
		return
	}
	if err := identity.Validate(); err != nil {
		l.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	status, ok := l.stageGitLabK8sBasename(w, r, req.Basename, identity, req.Metadata)
	if !ok {
		return
	}

	l.logger.InfoContext(r.Context(), "gitlab_k8s_staging_put",
		"basename", req.Basename,
		"job_identity", identity,
		"status", status,
	)
	l.writeJSON(r.Context(), w, http.StatusOK, map[string]string{"status": status})
}

func (l *Listener) stageGitLabK8sBasename(w http.ResponseWriter, r *http.Request, basename string, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata) (status string, ok bool) {
	if err := l.jobRegistry.StageCgroupBasenameForJob(r.Context(), basename, identity); err == nil {
		return "staged", true
	} else if !errors.Is(err, jobregistry.ErrJobNotFound) {
		l.logger.ErrorContext(r.Context(), "gitlab_k8s_staging_put_failed", "error", err)
		l.writeError(w, r, http.StatusInternalServerError, "internal error")
		return "", false
	}

	// Kubernetes/NRI has identity and cgroup basename in one request. Create
	// the GitLab host Job locally, then retry staging before returning to NRI.
	if _, err := l.jobRegistry.ApplyGitLabHostStart(r.Context(), identity, metadata, l.runnerType, l.hostManagerConn, l.hostManagerClient); err != nil {
		l.writeStartError(w, r, "gitlab_k8s_host_start_failed", err)
		return "", false
	}
	if err := l.jobRegistry.StageCgroupBasenameForJob(r.Context(), basename, identity); err != nil {
		if errors.Is(err, jobregistry.ErrJobNotFound) {
			l.writeError(w, r, http.StatusNotFound, "job_not_found")
			return "", false
		}
		l.logger.ErrorContext(r.Context(), "gitlab_k8s_staging_put_failed", "error", err)
		l.writeError(w, r, http.StatusInternalServerError, "internal error")
		return "", false
	}
	return "staged", true
}

func (l *Listener) stageGitLabBasename(w http.ResponseWriter, r *http.Request, basename string, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata) (status string, ok bool) {
	if err := l.jobRegistry.StageCgroupBasenameForJob(r.Context(), basename, identity); err == nil {
		return "staged", true
	} else if !errors.Is(err, jobregistry.ErrJobNotFound) {
		l.logger.ErrorContext(r.Context(), "gitlab_staging_put_failed", "error", err)
		l.writeError(w, r, http.StatusInternalServerError, "internal error")
		return "", false
	}

	// GitLab Docker proxy sends labels identity and cgroup basename in one
	// staging request. If the Job is not registered yet, create the host Job
	// locally, then retry staging before returning to the proxy.
	if _, err := l.jobRegistry.ApplyGitLabHostStart(r.Context(), identity, metadata, l.runnerType, l.hostManagerConn, l.hostManagerClient); err != nil {
		l.writeStartError(w, r, "gitlab_staging_host_start_failed", err)
		return "", false
	}
	if err := l.jobRegistry.StageCgroupBasenameForJob(r.Context(), basename, identity); err != nil {
		if errors.Is(err, jobregistry.ErrJobNotFound) {
			l.writeError(w, r, http.StatusNotFound, "job_not_found")
			return "", false
		}
		l.logger.ErrorContext(r.Context(), "gitlab_staging_put_failed", "error", err)
		l.writeError(w, r, http.StatusInternalServerError, "internal error")
		return "", false
	}
	return "staged", true
}
