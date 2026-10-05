// Package managerclient talks to manager-side config and collector services.
package managerclient

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"connectrpc.com/connect"

	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1/managerv1beta1connect"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// fetchConfigTimeout bounds a single FetchConfig call. Set high enough
// to absorb a cold-start manager (e.g. Lambda / scale-from-zero) that
// can take tens of seconds to load baseline rules on first hit.
const fetchConfigTimeout = time.Minute

// ConfigClient wraps ConfigService.FetchConfig for host and project scopes.
type ConfigClient struct {
	client managerv1beta1connect.ConfigServiceClient
	logger *slog.Logger
}

// Connection is the manager endpoint and credential used by manager RPCs.
// Prefer Auth / Cached for OIDC; Token is the static manager-token path.
type Connection struct {
	BaseURL string
	Token   string
	Auth    ClientAuth
	// Cached is the force-refreshable OIDC source used for shutdown Summary.
	// When set, it must be the same TokenSource wired into Auth.
	Cached *CachedTokenSource
}

// ClientAuth returns the effective credential for Connect clients.
func (c Connection) ClientAuth() ClientAuth {
	if c.Auth.TokenSource != nil || c.Auth.Token != "" || c.Auth.TokenType == TokenTypeIDToken {
		auth := c.Auth
		if auth.TokenType == "" {
			if auth.TokenSource != nil {
				auth.TokenType = TokenTypeIDToken
			} else {
				auth.TokenType = TokenTypeManagerToken
			}
		}
		return auth
	}
	return StaticTokenAuth(c.Token)
}

// HasCredential reports whether a static token or TokenSource is configured.
func (c Connection) HasCredential() bool {
	auth := c.ClientAuth()
	return auth.Token != "" || auth.TokenSource != nil
}

// ForceRefreshIDToken remints and seeds the OIDC reuse cache when Cached is set.
// Manager-token connections are a no-op.
func (c Connection) ForceRefreshIDToken(ctx context.Context) error {
	if c.Cached == nil {
		return nil
	}
	return c.Cached.ForceRefresh(ctx)
}

// CloseOIDCCredential stops shared OIDC mint work after the final Summary flush.
func (c Connection) CloseOIDCCredential() {
	if c.Cached != nil {
		c.Cached.Close()
	}
}

// NewConfigClient validates the manager endpoint and builds the config client.
func NewConfigClient(logger *slog.Logger, conn Connection) (*ConfigClient, error) {
	if logger == nil {
		logger = slog.Default()
	}
	component := logger.With("component", "manager_client")
	parsed, err := validateManagerBaseURL(conn.BaseURL)
	if err != nil {
		return nil, err
	}
	warnIfInsecureManagerURL(component, parsed, conn.BaseURL)
	if !conn.HasCredential() {
		return nil, fmt.Errorf("manager credential is required")
	}
	return &ConfigClient{
		client: managerv1beta1connect.NewConfigServiceClient(
			NewConnectHTTPClient(),
			conn.BaseURL,
			ConnectClientOptionsWithAuth(conn.ClientAuth())...,
		),
		logger: component,
	}, nil
}

func validateManagerBaseURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("manager URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse manager URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("manager URL must use http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("manager URL must include a host")
	}
	return parsed, nil
}

func warnIfInsecureManagerURL(logger *slog.Logger, parsed *url.URL, raw string) {
	if parsed.Scheme != "http" {
		return
	}
	logger.WarnContext(context.Background(), "manager_url_insecure_scheme",
		"manager_url", raw,
		"note", "manager URL uses plain http",
	)
}

// FetchResult is the manager response in agent-friendly types.
type FetchResult struct {
	ConfigRevision          string
	DefaultMaxAlertsPerRule int
	MonitorMode             bool
	RuleSources             []rulesource.LoadedRules
	OutputSettings          *managerv1beta1.OutputSettings
}

type RPCError struct {
	Code connect.Code
	Err  error
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("fetch manager config: %v", e.Err)
}

func (e *RPCError) Unwrap() error {
	return e.Err
}

// FetchConfig fetches manager config with a bounded per-call timeout.
func (c *ConfigClient) FetchConfig(ctx context.Context, req *managerv1beta1.FetchConfigRequest) (*FetchResult, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("manager client is nil")
	}
	if req == nil {
		return nil, fmt.Errorf("fetch config request is nil")
	}

	reqCtx, cancel := context.WithTimeout(ctx, fetchConfigTimeout)
	defer cancel()
	connectReq := connect.NewRequest(req)
	resp, err := c.client.FetchConfig(reqCtx, connectReq)
	if err != nil {
		return nil, &RPCError{Code: connect.CodeOf(err), Err: err}
	}

	ruleSources := protoconv.FromProtoRuleSources(resp.Msg.RuleSources)
	if !hasRule(ruleSources) {
		c.logger.WarnContext(ctx, "manager_config_empty_rules",
			"config_revision", resp.Msg.GetConfig().GetConfigRevision(),
		)
	}
	config := resp.Msg.GetConfig()

	return &FetchResult{
		ConfigRevision:          config.GetConfigRevision(),
		DefaultMaxAlertsPerRule: int(config.GetDefaultMaxAlertsPerRule()),
		MonitorMode:             config.GetMonitorMode(),
		RuleSources:             ruleSources,
		OutputSettings:          config.GetOutputSettings(),
	}, nil
}

func hasRule(sources []rulesource.LoadedRules) bool {
	for _, source := range sources {
		for _, set := range source.RuleSets {
			if len(set.Rules) > 0 {
				return true
			}
		}
	}
	return false
}
