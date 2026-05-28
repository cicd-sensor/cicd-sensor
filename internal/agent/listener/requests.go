package listener

import (
	"errors"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/projectconfig"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
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
	RuleSources             []rulesource.LoadedRules `json:"rule_sources,omitempty"`
	ManagerURL              string                   `json:"manager_url,omitempty"`
	ManagerToken            string                   `json:"manager_token,omitempty"`
	DebugEnabled            bool                     `json:"debug_enabled,omitempty"`
}

func (r *githubProjectStartRequest) Validate() error {
	var errs []error
	switch {
	case r.ManagerURL == "" && r.ManagerToken != "":
		errs = append(errs, errors.New("manager_token requires manager_url"))
	case r.ManagerURL != "" && r.ManagerToken == "":
		errs = append(errs, errors.New("manager_url requires manager_token"))
	case r.ManagerURL != "" && !managerauth.IsValidToken(r.ManagerToken):
		errs = append(errs, errors.New(managerauth.ValidTokenDescription()))
	}
	if r.ManagerURL != "" && r.DisableBaselineRules {
		errs = append(errs, errors.New("disable_baseline_rules cannot be combined with manager_url"))
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
