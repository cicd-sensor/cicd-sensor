package manager

import (
	"context"
	"fmt"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"

	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1/managerv1beta1connect"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// configServiceHandler serves startup config plus rules loaded at request time.
// Local rules may change while the manager is running; output settings do not.
type configServiceHandler struct {
	server *Server
}

func newConfigServiceHandler(s *Server) managerv1beta1connect.ConfigServiceHandler {
	return &configServiceHandler{server: s}
}

// FetchConfig handles ConfigService.FetchConfig.
func (h *configServiceHandler) FetchConfig(ctx context.Context, req *connect.Request[managerv1beta1.FetchConfigRequest]) (*connect.Response[managerv1beta1.FetchConfigResponse], error) {
	if err := protovalidate.Validate(req.Msg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid request: %w", err))
	}
	identity := protoconv.FromProtoJobIdentity(req.Msg.JobIdentity)
	if err := identity.Validate(); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid job identity: %w", err))
	}

	config := h.server.config
	if config == nil {
		h.server.logger.ErrorContext(ctx, "config_load_failed", "error", "startup config was not loaded")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("config load failed"))
	}

	sources, err := h.server.localRules.Load(ctx)
	if err != nil {
		h.server.logger.ErrorContext(ctx, "manager_rules_load_failed", "error", err)
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("manager rules load failed: %w", err))
	}
	baselineSource, err := h.server.baselineRules.LoadForProvider(ctx, h.server.logger, string(identity.Provider))
	if err != nil {
		h.server.logger.ErrorContext(ctx, "baseline_fetch_failed", "error", err)
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("baseline fetch failed: %w", err))
	}
	// Baseline first, then manual --rules-file. Rule source boundaries are
	// preserved so OCI/local revisions remain visible to the agent.
	merged := make([]rulesource.LoadedRules, 0, len(sources)+1)
	merged = append(merged, baselineSource)
	merged = append(merged, sources...)
	sources = merged

	out := &managerv1beta1.FetchConfigResponse{
		Config: &managerv1beta1.ServedConfig{
			ConfigRevision:          config.ConfigRevision,
			DefaultMaxAlertsPerRule: int32(config.DefaultMaxAlertsPerRule),
			OutputSettings:          config.OutputSettings,
		},
		RuleSources: protoconv.ToProtoRuleSources(sources),
	}
	return connect.NewResponse(out), nil
}
