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

// handleGitLabStagingPut selects the Job from evidence sent by the proxy:
// peer PID first, labels identity only when peer lookup misses.
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

	status, ok := l.stageGitLabBasename(w, r, req.Basename, labelsIdentity)
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

func (l *Listener) stageGitLabBasename(w http.ResponseWriter, r *http.Request, basename string, identity jobcontext.JobIdentity) (status string, ok bool) {
	if err := l.jobRegistry.StageCgroupBasenameForJob(r.Context(), basename, identity); err != nil {
		if errors.Is(err, jobregistry.ErrJobNotFound) {
			// The GitLab proxy uses 404 to lazy-create the Job and retry.
			l.writeError(w, r, http.StatusNotFound, "job_not_found")
			return "", false
		}
		l.logger.ErrorContext(r.Context(), "gitlab_staging_put_failed", "error", err)
		l.writeError(w, r, http.StatusInternalServerError, "internal error")
		return "", false
	}
	return "staged", true
}
