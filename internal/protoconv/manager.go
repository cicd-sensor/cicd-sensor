// Package protoconv converts between domain types and generated proto types.
// It does not own validation, redaction, or output policy.
package protoconv

import (
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// ToProtoJobIdentity converts a jobcontext.JobIdentity to the manager proto shape.
func ToProtoJobIdentity(id jobcontext.JobIdentity) *managerv1.JobIdentity {
	return &managerv1.JobIdentity{
		Provider:               string(id.Provider),
		ProviderHost:           id.ProviderHost,
		ProjectPath:            id.ProjectPath,
		GithubRunId:            id.GitHubRunID,
		GithubJob:              id.GitHubJob,
		GithubRunAttempt:       id.GitHubRunAttempt,
		GithubRunnerTrackingId: id.GitHubRunnerTrackingID,
		GitlabJobId:            id.GitLabJobID,
	}
}

// FromProtoJobIdentity converts the manager proto shape to jobcontext.JobIdentity.
func FromProtoJobIdentity(id *managerv1.JobIdentity) jobcontext.JobIdentity {
	if id == nil {
		return jobcontext.JobIdentity{}
	}
	return jobcontext.JobIdentity{
		Provider:               jobcontext.Provider(id.Provider),
		ProviderHost:           id.ProviderHost,
		ProjectPath:            id.ProjectPath,
		GitHubRunID:            id.GithubRunId,
		GitHubJob:              id.GithubJob,
		GitHubRunAttempt:       id.GithubRunAttempt,
		GitHubRunnerTrackingID: id.GithubRunnerTrackingId,
		GitLabJobID:            id.GitlabJobId,
	}
}

func ToProtoScope(scope jobcontext.ScopeType) managerv1.Scope {
	switch scope {
	case jobcontext.ScopeTypeHost:
		return managerv1.Scope_SCOPE_HOST
	case jobcontext.ScopeTypeProject:
		return managerv1.Scope_SCOPE_PROJECT
	default:
		return managerv1.Scope_SCOPE_UNSPECIFIED
	}
}

func ToProtoRuleSources(in []rulesource.LoadedRules) []*managerv1.RuleSource {
	out := make([]*managerv1.RuleSource, 0, len(in))
	for _, source := range in {
		out = append(out, &managerv1.RuleSource{
			RuleSets:      toProtoRuleSets(source.RuleSets),
			RuleModifiers: toProtoRuleModifiers(source.RuleModifiers),
		})
	}
	return out
}

func FromProtoRuleSources(in []*managerv1.RuleSource) []rulesource.LoadedRules {
	out := make([]rulesource.LoadedRules, 0, len(in))
	for _, source := range in {
		if source == nil {
			out = append(out, rulesource.LoadedRules{})
			continue
		}
		out = append(out, rulesource.LoadedRules{
			RuleSets:      fromProtoRuleSets(source.RuleSets),
			RuleModifiers: fromProtoRuleModifiers(source.RuleModifiers),
		})
	}
	return out
}

func toProtoRuleSets(in []rule.RuleSet) []*managerv1.RuleSet {
	out := make([]*managerv1.RuleSet, 0, len(in))
	for _, set := range in {
		out = append(out, toProtoRuleSet(set))
	}
	return out
}

func fromProtoRuleSets(in []*managerv1.RuleSet) []rule.RuleSet {
	out := make([]rule.RuleSet, 0, len(in))
	for _, set := range in {
		out = append(out, fromProtoRuleSet(set))
	}
	return out
}

func toProtoRuleSet(in rule.RuleSet) *managerv1.RuleSet {
	return &managerv1.RuleSet{
		RulesetId: in.RulesetID,
		Lists:     toProtoLists(in.Lists),
		Rules:     toProtoRules(in.Rules),
		Revision:  in.Revision,
	}
}

func fromProtoRuleSet(in *managerv1.RuleSet) rule.RuleSet {
	if in == nil {
		return rule.RuleSet{}
	}
	return rule.RuleSet{
		RulesetID: in.RulesetId,
		Lists:     fromProtoLists(in.Lists),
		Rules:     fromProtoRules(in.Rules),
		Revision:  in.Revision,
	}
}

func toProtoRules(in []rule.Rule) []*managerv1.Rule {
	out := make([]*managerv1.Rule, 0, len(in))
	for _, r := range in {
		out = append(out, toProtoRule(r))
	}
	return out
}

func fromProtoRules(in []*managerv1.Rule) []rule.Rule {
	out := make([]rule.Rule, 0, len(in))
	for _, r := range in {
		out = append(out, fromProtoRule(r))
	}
	return out
}

func toProtoRule(in rule.Rule) *managerv1.Rule {
	return &managerv1.Rule{
		RuleId:      in.RuleID,
		RuleName:    in.RuleName,
		Description: in.Description,
		Type:        in.Type,
		EventType:   string(in.EventType),
		Target:      toProtoRuleTarget(in.Target),
		Condition:   in.Condition,
		Exceptions:  in.Exceptions,
		MaxAlerts:   int32(in.MaxAlerts),
		Action:      string(in.Action),
		Tags:        copyStringMap(in.Tags),
	}
}

func fromProtoRule(in *managerv1.Rule) rule.Rule {
	if in == nil {
		return rule.Rule{}
	}
	return rule.Rule{
		RuleID:      in.RuleId,
		RuleName:    in.RuleName,
		Description: in.Description,
		Type:        in.Type,
		EventType:   jobevent.Type(in.EventType),
		Target:      fromProtoRuleTarget(in.Target),
		Condition:   in.Condition,
		Exceptions:  in.Exceptions,
		MaxAlerts:   int(in.MaxAlerts),
		Action:      rule.RuleAction(in.Action),
		Tags:        copyStringMap(in.Tags),
	}
}

func toProtoRuleModifiers(in []rule.RuleModifier) []*managerv1.RuleModifier {
	out := make([]*managerv1.RuleModifier, 0, len(in))
	for _, modifier := range in {
		out = append(out, toProtoRuleModifier(modifier))
	}
	return out
}

func fromProtoRuleModifiers(in []*managerv1.RuleModifier) []rule.RuleModifier {
	out := make([]rule.RuleModifier, 0, len(in))
	for _, modifier := range in {
		out = append(out, fromProtoRuleModifier(modifier))
	}
	return out
}

func toProtoRuleModifier(in rule.RuleModifier) *managerv1.RuleModifier {
	out := &managerv1.RuleModifier{
		ModifierId:       in.ModifierID,
		Revision:         in.Revision,
		Description:      in.Description,
		Targets:          toProtoRuleModifierTargets(in.Targets),
		AddExceptions:    in.AddExceptions,
		AddTargetExclude: toProtoRuleTargetMatchers(in.AddTargetExclude),
	}
	if in.OverrideAction != nil {
		value := string(*in.OverrideAction)
		out.OverrideAction = &value
	}
	if in.OverrideMaxAlerts != nil {
		value := int32(*in.OverrideMaxAlerts)
		out.OverrideMaxAlerts = &value
	}
	if in.Disable != nil {
		value := *in.Disable
		out.Disable = &value
	}
	return out
}

func fromProtoRuleModifier(in *managerv1.RuleModifier) rule.RuleModifier {
	if in == nil {
		return rule.RuleModifier{}
	}
	out := rule.RuleModifier{
		ModifierID:       in.ModifierId,
		Revision:         in.Revision,
		Description:      in.Description,
		Targets:          fromProtoRuleModifierTargets(in.Targets),
		AddExceptions:    in.AddExceptions,
		AddTargetExclude: fromProtoRuleTargetMatchers(in.AddTargetExclude),
	}
	if in.OverrideAction != nil {
		value := rule.RuleAction(in.GetOverrideAction())
		out.OverrideAction = &value
	}
	if in.OverrideMaxAlerts != nil {
		value := int(in.GetOverrideMaxAlerts())
		out.OverrideMaxAlerts = &value
	}
	if in.Disable != nil {
		value := in.GetDisable()
		out.Disable = &value
	}
	return out
}

func toProtoRuleTarget(in rule.RuleTarget) *managerv1.RuleTarget {
	if in.IsZero() {
		return nil
	}
	return &managerv1.RuleTarget{
		Include: toProtoRuleTargetMatchers(in.Include),
		Exclude: toProtoRuleTargetMatchers(in.Exclude),
	}
}

func fromProtoRuleTarget(in *managerv1.RuleTarget) rule.RuleTarget {
	if in == nil {
		return rule.RuleTarget{}
	}
	return rule.RuleTarget{
		Include: fromProtoRuleTargetMatchers(in.Include),
		Exclude: fromProtoRuleTargetMatchers(in.Exclude),
	}
}

func toProtoRuleTargetMatchers(in []rule.RuleTargetMatcher) []*managerv1.RuleTargetMatcher {
	out := make([]*managerv1.RuleTargetMatcher, 0, len(in))
	for _, matcher := range in {
		out = append(out, &managerv1.RuleTargetMatcher{
			ProviderHost: matcher.ProviderHost,
			Path:         matcher.Path,
		})
	}
	return out
}

func fromProtoRuleTargetMatchers(in []*managerv1.RuleTargetMatcher) []rule.RuleTargetMatcher {
	out := make([]rule.RuleTargetMatcher, 0, len(in))
	for _, matcher := range in {
		if matcher == nil {
			out = append(out, rule.RuleTargetMatcher{})
			continue
		}
		out = append(out, rule.RuleTargetMatcher{
			ProviderHost: matcher.ProviderHost,
			Path:         matcher.Path,
		})
	}
	return out
}

func toProtoRuleModifierTargets(in []rule.RuleModifierTarget) []*managerv1.RuleModifierTarget {
	out := make([]*managerv1.RuleModifierTarget, 0, len(in))
	for _, target := range in {
		out = append(out, &managerv1.RuleModifierTarget{
			RulesetId: target.RulesetID,
			RuleId:    target.RuleID,
		})
	}
	return out
}

func fromProtoRuleModifierTargets(in []*managerv1.RuleModifierTarget) []rule.RuleModifierTarget {
	out := make([]rule.RuleModifierTarget, 0, len(in))
	for _, target := range in {
		if target == nil {
			out = append(out, rule.RuleModifierTarget{})
			continue
		}
		out = append(out, rule.RuleModifierTarget{
			RulesetID: target.RulesetId,
			RuleID:    target.RuleId,
		})
	}
	return out
}

func toProtoLists(in map[string][]string) map[string]*managerv1.StringList {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*managerv1.StringList, len(in))
	for key, values := range in {
		out[key] = &managerv1.StringList{Values: append([]string(nil), values...)}
	}
	return out
}

func fromProtoLists(in map[string]*managerv1.StringList) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for key, values := range in {
		if values == nil {
			out[key] = nil
			continue
		}
		out[key] = append([]string(nil), values.Values...)
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
