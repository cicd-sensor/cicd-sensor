package main

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/cicd-sensor/cicd-sensor/internal/ctl/rulevalidate"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// runRuleValidate validates the same bundled YAML shape used by runtime.
func runRuleValidate(_ context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, newUsageError(2, "rule validate: at least one path is required")
	}

	files, skippedDirs, err := collectRuleFiles(args)
	if err != nil {
		return 2, err
	}
	for _, dir := range skippedDirs {
		fmt.Fprintf(stderr, "warning: %s: subdirectory skipped (rules dirs are flat)\n", dir.Path)
	}
	if len(files) == 0 {
		return 1, fmt.Errorf("rule validate: no YAML rule files found in %v", args)
	}

	bundle, err := buildRuleBundle(files)
	if err != nil {
		printValidationErrors(stderr, []validationError{{Path: "bundle", Message: err.Error()}})
		return 1, fmt.Errorf("rule validate: bundle failed validation")
	}
	loaded, err := rulesource.LoadRulesBytes(bundle, "validation")
	if err != nil {
		printValidationErrors(stderr, []validationError{{Path: "bundle", Message: err.Error()}})
		return 1, fmt.Errorf("rule validate: bundle failed validation")
	}
	resolved := rule.Resolve(rule.ResolveInput{
		RuleSets:      loaded.RuleSets,
		RuleModifiers: loaded.RuleModifiers,
	})
	printResolveWarnings(stderr, resolved.Warnings)

	env, err := celengine.NewEnv()
	if err != nil {
		return 2, fmt.Errorf("initialize CEL env: %w", err)
	}

	var (
		failures  []validationError
		costWarns []costWarning
	)

	for _, set := range loaded.RuleSets {
		compileErrors := rulevalidate.CompileSet(env, set)
		for _, compileErr := range compileErrors {
			failures = append(failures, validationError{
				Path:      "bundle",
				RulesetID: compileErr.Identity.RulesetID,
				RuleID:    compileErr.Identity.RuleID,
				Message:   compileErr.Reason,
			})
		}
		for key, cost := range rulevalidate.RuleSetCosts(env, set) {
			if cost > rulevalidate.CostWarnThreshold {
				costWarns = append(costWarns, costWarning{Path: "bundle", RulesetID: key.Identity.RulesetID, RuleID: key.Identity.RuleID, Kind: key.Kind, Cost: cost})
			}
		}
	}

	printValidationErrors(stderr, failures)
	sort.Slice(costWarns, func(i, j int) bool {
		if costWarns[i].Path != costWarns[j].Path {
			return costWarns[i].Path < costWarns[j].Path
		}
		if costWarns[i].RulesetID != costWarns[j].RulesetID {
			return costWarns[i].RulesetID < costWarns[j].RulesetID
		}
		if costWarns[i].RuleID != costWarns[j].RuleID {
			return costWarns[i].RuleID < costWarns[j].RuleID
		}
		return costWarns[i].Kind < costWarns[j].Kind
	})
	for _, w := range costWarns {
		fmt.Fprintf(stderr, "warning: %s: ruleset_id=%s rule_id=%s: %s estimated CEL cost %d exceeds %d (consider simplifying)\n",
			w.Path, w.RulesetID, w.RuleID, w.Kind, w.Cost, rulevalidate.CostWarnThreshold)
	}

	if len(failures) > 0 {
		return 1, fmt.Errorf("rule validate: bundle failed validation")
	}

	fmt.Fprintf(stdout, "OK: %d file(s) bundled and validated\n", len(files))
	return 0, nil
}

func printValidationErrors(stderr io.Writer, failures []validationError) {
	for _, failure := range failures {
		if failure.RulesetID != "" && failure.RuleID != "" {
			fmt.Fprintf(stderr, "error: %s: ruleset_id=%s rule_id=%s: %s\n", failure.Path, failure.RulesetID, failure.RuleID, failure.Message)
			continue
		}
		if failure.RulesetID != "" {
			fmt.Fprintf(stderr, "error: %s: ruleset_id=%s: %s\n", failure.Path, failure.RulesetID, failure.Message)
			continue
		}
		fmt.Fprintf(stderr, "error: %s: %s\n", failure.Path, failure.Message)
	}
}

func printResolveWarnings(stderr io.Writer, warnings []rule.ResolveWarning) {
	for _, warning := range warnings {
		if warning.Identity.RulesetID != "" && warning.Identity.RuleID != "" {
			fmt.Fprintf(stderr, "warning: bundle: ruleset_id=%s rule_id=%s: %s\n", warning.Identity.RulesetID, warning.Identity.RuleID, warning.Kind)
			continue
		}
		if warning.EntryLabel != "" {
			fmt.Fprintf(stderr, "warning: bundle: %s: %s\n", warning.EntryLabel, warning.Kind)
			continue
		}
		fmt.Fprintf(stderr, "warning: bundle: %s\n", warning.Kind)
	}
}

type costWarning struct {
	Path      string
	RulesetID string
	RuleID    string
	Kind      string // "condition" or "exception"
	Cost      uint64
}

type validationError struct {
	Path      string
	RulesetID string
	RuleID    string
	Message   string
}
