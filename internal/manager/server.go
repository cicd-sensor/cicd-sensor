package manager

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1/managerv1beta1connect"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/baseline"
)

// Server is the manager server that exposes Connect RPCs.
type Server struct {
	logger        *slog.Logger
	tokens        *TokenStore
	config        *ServedConfig
	baselineRules BaselineRuleSource
	localRules    *RuleSourceCache
	startup       *StartupConfig
	httpServer    *http.Server

	outputRouter *OutputRouter
	now          func() time.Time
}

// NewServer creates a manager server mounted on addr. Baseline and local rule
// caches are owned here so callers only pass startup intent, not cache objects.
func NewServer(logger *slog.Logger, addr string, tokens []string, config *ServedConfig, rulesPath string, startup *StartupConfig, router *OutputRouter) *Server {
	return newServer(logger, addr, tokens, config, baseline.NewCache(), NewRuleSourceCache(rulesPath), startup, router)
}

func newServer(logger *slog.Logger, addr string, tokens []string, config *ServedConfig, baselineRules BaselineRuleSource, localRules *RuleSourceCache, startup *StartupConfig, router *OutputRouter) *Server {
	s := &Server{
		logger:        logger.With("component", "manager"),
		tokens:        NewTokenStore(tokens),
		config:        config,
		baselineRules: baselineRules,
		localRules:    localRules,
		startup:       startup,
		outputRouter:  router,
		now:           time.Now,
	}

	mux := http.NewServeMux()
	configPath, configHandler := managerv1beta1connect.NewConfigServiceHandler(
		newConfigServiceHandler(s),
		connect.WithReadMaxBytes(managerMaxRequestBytes),
		connect.WithInterceptors(unaryOnlyInterceptor{}),
	)
	mux.Handle(configPath, configHandler)
	collectorPath, collectorHandler := managerv1beta1connect.NewCollectorServiceHandler(
		newCollectorServiceHandler(s),
		connect.WithReadMaxBytes(managerMaxRequestBytes),
		connect.WithInterceptors(unaryOnlyInterceptor{}),
	)
	mux.Handle(collectorPath, collectorHandler)

	// Auth is enforced at the HTTP layer via connectrpc/authn middleware so
	// unauthenticated requests are rejected before the Connect framework
	// decompresses or unmarshals the body. unaryOnlyInterceptor is a separate
	// defense-in-depth guard on the Connect handlers.
	authMiddleware := newAuthMiddleware(s.logger, s.tokens)

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: authMiddleware.Wrap(mux),
		// ReadHeaderTimeout bounds slowloris-style header stalls; the full
		// ReadTimeout then bounds the body read.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s
}

// managerMaxRequestBytes caps the Connect request body for unary RPCs. 16 MiB
// comfortably covers FetchConfig payloads (typed rule sources) while
// keeping DoS surface bounded.
const managerMaxRequestBytes = 16 * 1024 * 1024

// Handler exposes the composed http.Handler that carries the Connect
// service mounts and interceptors. Intended for integration tests that need
// to bypass the listener (e.g. httptest.NewServer).
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// Run starts the HTTP server and blocks until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	defer func() {
		if err := s.Close(); err != nil && s.logger != nil {
			s.logger.ErrorContext(ctx, "manager_output_router_close_failed", "error", err)
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		s.logger.InfoContext(ctx, "manager_server_started", "addr", s.httpServer.Addr)
		err := s.httpServer.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.ErrorContext(ctx, "manager_shutdown_request_abandoned", "error", err)
			return fmt.Errorf("server shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) Close() error {
	if s == nil || s.outputRouter == nil {
		return nil
	}
	return s.outputRouter.Close()
}
