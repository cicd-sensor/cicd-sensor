package listener

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/projectconfig"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

type githubHostStartRequest struct {
	jobcontext.JobIdentity
	Metadata jobcontext.JobMetadata `json:"metadata,omitempty"`
}

type githubJobIdentityRequest struct {
	jobcontext.JobIdentity
}

type githubProjectStartRequest struct {
	jobcontext.JobIdentity
	Metadata                jobcontext.JobMetadata   `json:"metadata,omitempty"`
	DefaultMaxAlertsPerRule int                      `json:"default_max_alerts_per_rule,omitempty"`
	DisableBaselineRules    bool                     `json:"disable_baseline_rules,omitempty"`
	MonitorMode             bool                     `json:"monitor_mode,omitempty"`
	RuleSources             []rulesource.LoadedRules `json:"rule_sources,omitempty"`
	ManagerURL              string                   `json:"manager_url,omitempty"`
	ManagerToken            string                   `json:"manager_token,omitempty"`
	ManagerAuth             string                   `json:"manager_auth,omitempty"`
	IDTokenRequestURL       string                   `json:"id_token_request_url,omitempty"`
	IDTokenRequestToken     string                   `json:"id_token_request_token,omitempty"`
	IDTokenAudience         string                   `json:"id_token_audience,omitempty"`
	DebugEnabled            bool                     `json:"debug_enabled,omitempty"`
}

func (r *githubProjectStartRequest) managerAuthMode() string {
	mode := strings.ToLower(strings.TrimSpace(r.ManagerAuth))
	switch mode {
	case "", "manager-token":
		return managerclient.TokenTypeManagerToken
	case "oidc":
		return managerclient.TokenTypeIDToken
	default:
		return mode
	}
}

func (r *githubProjectStartRequest) Validate() error {
	var errs []error
	mode := r.managerAuthMode()
	switch mode {
	case managerclient.TokenTypeManagerToken:
		switch {
		case r.ManagerURL == "" && r.ManagerToken != "":
			errs = append(errs, errors.New("manager_token requires manager_url"))
		case r.ManagerURL != "" && r.ManagerToken == "":
			errs = append(errs, errors.New("manager_url requires manager_token when manager_auth is manager-token"))
		}
		if r.IDTokenRequestURL != "" || r.IDTokenRequestToken != "" {
			errs = append(errs, errors.New("id_token_request_url/token require manager_auth=oidc"))
		}
	case managerclient.TokenTypeIDToken:
		if r.ManagerURL == "" {
			errs = append(errs, errors.New("manager_auth=oidc requires manager_url"))
		}
		if r.ManagerToken != "" {
			errs = append(errs, errors.New("manager_token cannot be combined with manager_auth=oidc"))
		}
		if strings.TrimSpace(r.IDTokenRequestURL) == "" {
			errs = append(errs, errors.New("manager_auth=oidc requires id_token_request_url"))
		}
		if strings.TrimSpace(r.IDTokenRequestToken) == "" {
			errs = append(errs, errors.New("manager_auth=oidc requires id_token_request_token"))
		}
	default:
		errs = append(errs, fmt.Errorf("unknown manager_auth %q (want manager-token or oidc)", r.ManagerAuth))
	}
	if r.ManagerURL != "" && r.DisableBaselineRules {
		errs = append(errs, errors.New("disable_baseline_rules cannot be combined with manager_url"))
	}
	if r.ManagerURL != "" && r.MonitorMode {
		errs = append(errs, errors.New("monitor_mode cannot be combined with manager_url"))
	}
	if r.ManagerURL == "" {
		cfg := projectconfig.ProjectConfig{DefaultMaxAlertsPerRule: &r.DefaultMaxAlertsPerRule}
		if err := cfg.Validate(); err != nil {
			errs = append(errs, err)
		}
		for i := range r.RuleSources {
			if err := r.RuleSources[i].Validate(); err != nil {
				errs = append(errs, fmt.Errorf("rule_sources[%d]: %w", i, err))
			}
		}
	}
	return errors.Join(errs...)
}
