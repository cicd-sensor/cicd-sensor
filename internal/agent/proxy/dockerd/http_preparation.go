package dockerd

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
)

func dockerStartID(req *http.Request, resource string) string {
	if req == nil || req.Method != http.MethodPost {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/"), "/")
	if len(parts) == 4 && strings.HasPrefix(parts[0], "v") {
		parts = parts[1:]
	}
	if len(parts) != 3 || parts[0] != resource || parts[2] != "start" || !fullDockerID(parts[1]) {
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

// Start responses are held only AFTER dockerd starts the container. GitLab
// Runner sends shell stdin after this response, so preparation precedes scripts
// without parsing or buffering them. Entrypoint code is already running.
func withHTTPPreparation(next *httputil.ReverseProxy, upstreamSocket, agentSocket string, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	preparation := httpprepare.NewRemote(agentSocket, logger)
	// Inspect and process-root lookup can block before inventory starts. Keep
	// this admission slot until the real operation ends, even after timeout.
	slots := make(chan struct{}, httpprepare.MaxConcurrent)
	prepare := func(ctx context.Context, id string, isExec bool) {
		ctx, cancel := context.WithTimeout(ctx, httpprepare.Budget)
		defer cancel()
		source := "docker-start"
		if isExec {
			source = "docker-exec"
		}
		started := time.Now()
		select {
		case slots <- struct{}{}:
			done := make(chan error, 1)
			go func() {
				defer func() { <-slots }()
				done <- prepareDockerTarget(ctx, upstreamSocket, id, isExec, preparation)
			}()
			var err error
			select {
			case err = <-done:
			case <-ctx.Done():
				err = ctx.Err()
			}
			logger.InfoContext(ctx, "docker_http_preparation", "source", source, "elapsed", time.Since(started), "error", err)
		default:
			logger.DebugContext(ctx, "docker_http_preparation_dropped", "source", source)
		}
	}
	previous := next.ModifyResponse
	next.ModifyResponse = func(resp *http.Response) error {
		if previous != nil {
			if err := previous(resp); err != nil {
				return err
			}
		}
		if resp.StatusCode == http.StatusNoContent {
			if id := dockerStartID(resp.Request, "containers"); id != "" {
				prepare(resp.Request.Context(), id, false)
			}
		}
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := dockerStartID(r, "exec"); id != "" {
			prepare(r.Context(), id, true)
		}
		next.ServeHTTP(w, r)
	})
}
