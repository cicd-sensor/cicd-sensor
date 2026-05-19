package listener

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
)

// decodeJSONBody accepts exactly one bounded JSON object.
func (l *Listener) decodeJSONBody(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, controlRequestBodyMaxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return errors.New("request body must contain a single JSON value")
}

// writeStartError maps routine lifecycle conflicts to 409.
func (l *Listener) writeStartError(w http.ResponseWriter, r *http.Request, logEvent string, err error) {
	switch {
	case errors.Is(err, jobregistry.ErrHostManagerRequired):
		l.writeError(w, r, http.StatusBadRequest, jobregistry.ErrHostManagerRequired.Error())
	case errors.Is(err, jobregistry.ErrHostAfterProject):
		l.writeError(w, r, http.StatusConflict, jobregistry.ErrHostAfterProject.Error())
	case errors.Is(err, job.ErrProjectScopeAlreadySet):
		l.writeError(w, r, http.StatusConflict, job.ErrProjectScopeAlreadySet.Error())
	case errors.Is(err, jobregistry.ErrJobAlreadyRegistered):
		l.writeError(w, r, http.StatusConflict, jobregistry.ErrJobAlreadyRegistered.Error())
	default:
		l.logger.ErrorContext(r.Context(), logEvent, "error", err)
		l.writeError(w, r, http.StatusInternalServerError, "internal error")
	}
}

func (l *Listener) writeJSON(ctx context.Context, w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		l.logger.WarnContext(ctx, "response_write_failed", "error", err)
	}
}

func (l *Listener) writeError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	l.logger.WarnContext(r.Context(), "request_rejected",
		"status", code,
		"error", msg,
	)
	l.writeJSON(r.Context(), w, code, map[string]string{"error": msg})
}
