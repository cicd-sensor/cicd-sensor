// Package rulesource loads user-authored rule YAML files.
package rulesource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

const ruleYAMLMaxBytes = 4 * 1024 * 1024

var (
	stableReadMaxAttempts  = 8
	stableReadInitialDelay = 50 * time.Millisecond
	// Test seam for stable-read retry paths; production always uses os.Root.
	readRootFile = readRootFileOS
	sleep        = time.Sleep
)

// LoadedRules is the rule-only result of reading rule source files.
type LoadedRules struct {
	RuleSets      []rule.RuleSet
	RuleModifiers []rule.RuleModifier
}

func (r LoadedRules) Validate() error {
	for i := range r.RuleSets {
		if err := rule.ValidateRuleSet(&r.RuleSets[i]); err != nil {
			return fmt.Errorf("rule_sets[%d]: %w", i, err)
		}
	}
	for i := range r.RuleModifiers {
		if err := rule.ValidateRuleModifier(&r.RuleModifiers[i]); err != nil {
			return fmt.Errorf("rule_modifiers[%d]: %w", i, err)
		}
	}
	return nil
}

// IsRuleFileName reports whether name has a rule YAML file extension.
func IsRuleFileName(name string) bool {
	return isYAMLName(name)
}

// LoadRulesFile reads, parses, and validates one YAML rule source file.
func LoadRulesFile(path string) (*LoadedRules, error) {
	clean := filepath.Clean(path)
	dir := filepath.Dir(clean)
	name := filepath.Base(clean)

	delay := stableReadInitialDelay
	for attempt := 1; attempt <= stableReadMaxAttempts; attempt++ {
		first, err := readRootFile(dir, name)
		if err != nil {
			return nil, fmt.Errorf("read rule file %s: %w", name, err)
		}
		firstSum := sha256.Sum256(first)
		revision := "sha256:" + hex.EncodeToString(firstSum[:])
		loaded, parseErr := loadRulesBytes(name, first, revision)
		second, err := readRootFile(dir, name)
		if err != nil {
			return nil, fmt.Errorf("read rule file %s: %w", name, err)
		}
		secondSum := sha256.Sum256(second)
		if firstSum != secondSum {
			if attempt == stableReadMaxAttempts {
				return nil, fmt.Errorf("read rule file %s: rule file changed during read", name)
			}
			sleep(delay)
			delay *= 2
			continue
		}
		if parseErr != nil {
			return nil, parseErr
		}
		return loaded, nil
	}
	return nil, fmt.Errorf("read rule file %s: rule file changed during read", name)
}

// LoadRulesBytes parses and validates a bundled rule YAML document.
func LoadRulesBytes(data []byte, revision string) (*LoadedRules, error) {
	return loadRulesBytes("rule bundle", data, revision)
}

func loadRulesBytes(name string, data []byte, revision string) (*LoadedRules, error) {
	if len(data) > ruleYAMLMaxBytes {
		return nil, fmt.Errorf("rule yaml size %d exceeds %d bytes", len(data), ruleYAMLMaxBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	loaded := &LoadedRules{}
	foundDocument := false
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse rule file %s: %w", name, err)
		}
		if isEmptyDocument(&node) {
			continue
		}
		parsed, err := parseRuleDocument(name, &node)
		if err != nil {
			return nil, err
		}
		foundDocument = true
		loaded.RuleSets = append(loaded.RuleSets, parsed.RuleSets...)
		loaded.RuleModifiers = append(loaded.RuleModifiers, parsed.RuleModifiers...)
	}
	if !foundDocument {
		return nil, fmt.Errorf("rule file %s: must contain rule_sets or rule_modifiers", name)
	}
	for i := range loaded.RuleSets {
		loaded.RuleSets[i].Revision = revision
	}
	for i := range loaded.RuleModifiers {
		loaded.RuleModifiers[i].Revision = revision
	}
	return loaded, nil
}

func parseRuleDocument(name string, node *yaml.Node) (*LoadedRules, error) {
	var top map[string]yaml.Node
	if err := node.Decode(&top); err != nil {
		return nil, fmt.Errorf("parse rule file %s: %w", name, err)
	}
	_, hasRuleSets := top["rule_sets"]
	_, hasRuleModifiers := top["rule_modifiers"]
	if hasRuleSets && hasRuleModifiers {
		return nil, fmt.Errorf("rule file %s: must not contain both rule_sets and rule_modifiers", name)
	}
	if !hasRuleSets && !hasRuleModifiers {
		return nil, fmt.Errorf("rule file %s: must contain rule_sets or rule_modifiers", name)
	}

	loaded := &LoadedRules{}
	if hasRuleSets {
		var doc struct {
			RuleSets []rule.RuleSet `yaml:"rule_sets"`
		}
		if err := node.Decode(&doc); err != nil {
			return nil, fmt.Errorf("parse rule file %s: %w", name, err)
		}
		for _, ruleSet := range doc.RuleSets {
			if err := rule.ValidateRuleSet(&ruleSet); err != nil {
				return nil, fmt.Errorf("validate rule file %s: %w", name, err)
			}
		}
		loaded.RuleSets = doc.RuleSets
		return loaded, nil
	}

	var doc struct {
		RuleModifiers []rule.RuleModifier `yaml:"rule_modifiers"`
	}
	if err := node.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse rule file %s: %w", name, err)
	}
	for _, modifier := range doc.RuleModifiers {
		if err := rule.ValidateRuleModifier(&modifier); err != nil {
			return nil, fmt.Errorf("validate rule file %s: %w", name, err)
		}
	}
	loaded.RuleModifiers = doc.RuleModifiers
	return loaded, nil
}

func readRootFileOS(dir string, name string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(name)
}

func ruleRevision(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isEmptyDocument(node *yaml.Node) bool {
	if node == nil {
		return true
	}
	if node.Kind == 0 {
		return true
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) == 0 {
		return true
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		return isEmptyDocument(node.Content[0])
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return true
	}
	if node.Kind == yaml.MappingNode && len(node.Content) == 0 {
		return true
	}
	return false
}

func isYAMLName(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}
