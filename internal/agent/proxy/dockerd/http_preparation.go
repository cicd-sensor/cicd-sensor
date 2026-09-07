package dockerd

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
)

func execStartID(req *http.Request) string {
	if req == nil || req.Method != http.MethodPost {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/"), "/")
	if len(parts) == 4 && strings.HasPrefix(parts[0], "v") {
		parts = parts[1:]
	}
	if len(parts) != 3 || parts[0] != "exec" || parts[2] != "start" || !fullDockerID(parts[1]) {
		return ""
	}
	return parts[1]
}
func fullDockerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Wrapping the reverse proxy leaves hijacked/streaming exec responses intact.
// Only the start request waits; create staging and unrelated requests are unchanged.
func withHTTPPreparation(next http.Handler, upstreamSocket, agentSocket string, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	preparation := httpprepare.NewRemote(agentSocket, logger)
	// Inspect/root acquisition can block too; retain slots until they finish.
	slots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := execStartID(r); id != "" {
			prepareCtx, cancel := context.WithTimeout(r.Context(), httpprepare.Budget)
			select {
			case slots <- struct{}{}:
				done := make(chan error, 1)
				go func() {
					defer func() { <-slots }()
					done <- prepareDockerExec(prepareCtx, upstreamSocket, id, preparation)
				}()
				var err error
				select {
				case err = <-done:
				case <-prepareCtx.Done():
					err = prepareCtx.Err()
				}
				if err != nil {
					logger.DebugContext(r.Context(), "docker_exec_http_preparation_incomplete", "exec_id", id, "error", err)
				}
			default:
				logger.DebugContext(r.Context(), "docker_exec_http_preparation_dropped")
			}
			cancel()
		}
		next.ServeHTTP(w, r)
	})
}
