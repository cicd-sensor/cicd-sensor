// Package jobscope owns per-scope runtime state. Job identity and metadata
// stay owned by Job and are passed in at output boundaries.
package jobscope

import (
	"errors"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/joblogs"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/observations"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// ErrScopeTypeMismatch reports that an operation received a scope of the
// wrong type (host where project was expected, or vice versa).
var ErrScopeTypeMismatch = errors.New("scope type mismatch")

// JobScopeState holds the configuration and runtime state for one scope.
// Dispatch-path methods tolerate nil receivers; direct state access assumes
// NewHost or NewProject constructed the value.
type JobScopeState struct {
	Type           jobcontext.ScopeType
	RuleSets       []rule.RuleSet
	RuleModifiers  []rule.RuleModifier
	ConfigRevision string
	OutputSettings *managerv1.OutputSettings
	ResolvedRules  rule.ResolvedRules
	Observations   *observations.State
	managerJobLogs joblogs.ManagerJobLogs
	debugOutput    *joblogs.DebugOutput
	// Zero means this scope did not configure a default; rule.Merge uses the system fallback.
	DefaultMaxAlertsPerRule int
}

// ProjectLocalConfig is only for project-local mode. Manager-backed project
// starts ignore project-local rules/defaults in the agent.
type ProjectLocalConfig struct {
	RuleSources             []rulesource.LoadedRules
	DefaultMaxAlertsPerRule int
}

// ManagerConfig is the config payload returned by cicd-sensor-manager.
type ManagerConfig struct {
	RuleSources             []rulesource.LoadedRules
	ConfigRevision          string
	OutputSettings          *managerv1.OutputSettings
	DefaultMaxAlertsPerRule int
}

func NewHost() *JobScopeState {
	return &JobScopeState{
		Type:         jobcontext.ScopeTypeHost,
		Observations: observations.NewState(),
	}
}

func NewProject() *JobScopeState {
	return &JobScopeState{
		Type:         jobcontext.ScopeTypeProject,
		Observations: observations.NewState(),
	}
}

func (s *JobScopeState) SetManagerJobLogs(logs joblogs.ManagerJobLogs) {
	s.managerJobLogs = logs
}

func (s *JobScopeState) SetDebugOutput(output *joblogs.DebugOutput) {
	s.debugOutput = output
}

func (s *JobScopeState) ManagerJobLogsForTesting() *joblogs.ManagerJobLogs {
	return &s.managerJobLogs
}

func (s *JobScopeState) ApplyProjectLocalConfig(cfg ProjectLocalConfig) error {
	if s == nil {
		return errors.New("nil scope")
	}
	for _, source := range cfg.RuleSources {
		s.RuleSets = append(s.RuleSets, source.RuleSets...)
		s.RuleModifiers = append(s.RuleModifiers, source.RuleModifiers...)
	}
	if cfg.DefaultMaxAlertsPerRule != 0 {
		s.DefaultMaxAlertsPerRule = cfg.DefaultMaxAlertsPerRule
	}
	return nil
}

func (s *JobScopeState) ApplyManagerConfig(cfg ManagerConfig) error {
	if s == nil {
		return errors.New("nil scope")
	}
	for _, source := range cfg.RuleSources {
		s.RuleSets = append(s.RuleSets, source.RuleSets...)
		s.RuleModifiers = append(s.RuleModifiers, source.RuleModifiers...)
	}
	s.ConfigRevision = cfg.ConfigRevision
	s.OutputSettings = cfg.OutputSettings
	if cfg.DefaultMaxAlertsPerRule != 0 {
		s.DefaultMaxAlertsPerRule = cfg.DefaultMaxAlertsPerRule
	}
	return nil
}

func (s *JobScopeState) ApplyBaselineRules(source rulesource.LoadedRules) error {
	if s == nil {
		return errors.New("nil scope")
	}
	s.RuleSets = append(s.RuleSets, source.RuleSets...)
	s.RuleModifiers = append(s.RuleModifiers, source.RuleModifiers...)
	return nil
}

func (s *JobScopeState) ResolveRules(identity jobcontext.JobIdentity) {
	s.ResolvedRules = rule.Merge(rule.MergeInput{
		RuleSets:                s.RuleSets,
		RuleModifiers:           s.RuleModifiers,
		DefaultMaxAlertsPerRule: s.DefaultMaxAlertsPerRule,
		ProviderHost:            identity.ProviderHost,
		ProjectPath:             identity.ProjectPath,
	})
}

func (s *JobScopeState) ObservationSnapshot() observations.StateSnapshot {
	return s.Observations.Snapshot()
}

func (s *JobScopeState) CorrelationHitCountFor(identity rule.RuleIdentity) int64 {
	if s == nil || s.Observations == nil {
		return 0
	}
	return s.Observations.CorrelationHitCountFor(identity)
}

func (s *JobScopeState) RecordHit(hit observations.HitEntry, event jobevent.EventRecord) {
	if s == nil || s.Observations == nil || hit.Identity.IsZero() {
		return
	}
	s.Observations.FeedHit(hit, event)
}

func (s *JobScopeState) resolvedRuleInfo(identity rule.RuleIdentity) (name, description, revision string) {
	resolved, found := s.ResolvedRules.Lookup(identity)
	if !found {
		return "", "", ""
	}
	return resolved.Rule.RuleName, resolved.Rule.Description, resolved.RulesetRevision
}
