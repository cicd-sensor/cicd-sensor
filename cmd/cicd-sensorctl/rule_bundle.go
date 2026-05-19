package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func runRuleBundle(_ context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	opts, err := parseRuleBundleArgs(args, stderr)
	if err != nil {
		return 2, err
	}
	if opts.help {
		return 0, nil
	}
	if err := validateRuleBundlePath(opts.rulesDir, opts.outputPath); err != nil {
		return 2, err
	}

	files, skippedDirs, err := collectRuleDirectoryFiles(opts.rulesDir)
	if err != nil {
		return 2, err
	}
	for _, dir := range skippedDirs {
		fmt.Fprintf(stderr, "warning: %s: subdirectory skipped (rules dirs are flat)\n", dir.Path)
	}
	if len(files) == 0 {
		return 1, fmt.Errorf("rule bundle: no YAML rule files found in %s", opts.rulesDir)
	}

	bundle, err := buildRuleBundle(files)
	if err != nil {
		return 1, err
	}
	if err := os.WriteFile(opts.outputPath, bundle, 0o644); err != nil {
		return 1, fmt.Errorf("write rule bundle %s: %w", opts.outputPath, err)
	}

	fmt.Fprintf(stdout, "OK: %d file(s) bundled into %s\n", len(files), opts.outputPath)
	fmt.Fprintf(stdout, "Next: cicd-sensorctl rule validate %s\n", opts.outputPath)
	return 0, nil
}

type ruleBundleOptions struct {
	rulesDir   string
	outputPath string
	help       bool
}

func parseRuleBundleArgs(args []string, stderr io.Writer) (ruleBundleOptions, error) {
	var opts ruleBundleOptions
	fs := flag.NewFlagSet("rule bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: cicd-sensorctl rule bundle --input-dir DIR --output PATH")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Input:")
		fmt.Fprintln(fs.Output(), "  --input-dir DIR")
		fmt.Fprintln(fs.Output(), "        Flat directory containing .yaml/.yml rule files.")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Required:")
		fmt.Fprintln(fs.Output(), "  --output PATH")
		fmt.Fprintln(fs.Output(), "        File to write the bundled rule YAML to. Must not already exist.")
	}
	fs.StringVar(&opts.rulesDir, "input-dir", "", "Flat directory containing rule YAML files.")
	fs.StringVar(&opts.outputPath, "output", "", "File to write bundled rule YAML to.")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.help = true
			return opts, nil
		}
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, newUsageError(2, "rule bundle: unexpected positional arguments")
	}
	if opts.rulesDir == "" {
		return opts, newUsageError(2, "rule bundle: --input-dir is required")
	}
	if opts.outputPath == "" {
		return opts, newUsageError(2, "rule bundle: --output is required")
	}
	return opts, nil
}

func validateRuleBundlePath(rulesDir string, outputPath string) error {
	info, err := os.Stat(rulesDir)
	if err != nil {
		return fmt.Errorf("stat rules directory %s: %w", rulesDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("rule bundle: %s is not a directory", rulesDir)
	}
	if _, err := os.Stat(outputPath); err == nil {
		return fmt.Errorf("rule bundle: output path already exists: %s", outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat output path %s: %w", outputPath, err)
	}

	rulesAbs, err := filepath.Abs(rulesDir)
	if err != nil {
		return fmt.Errorf("resolve rules directory %s: %w", rulesDir, err)
	}
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path %s: %w", outputPath, err)
	}
	rel, err := filepath.Rel(rulesAbs, outputAbs)
	if err != nil {
		return fmt.Errorf("compare output path %s with rules directory %s: %w", outputPath, rulesDir, err)
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return fmt.Errorf("rule bundle: output path must be outside the input rules directory")
	}
	return nil
}

func buildRuleBundle(files []ruleFile) ([]byte, error) {
	var buf bytes.Buffer
	for i, file := range files {
		if !rulesource.IsRuleFileName(file.Name) {
			return nil, fmt.Errorf("%s: not a YAML file (expected .yaml/.yml)", file.Path)
		}
		body, err := os.ReadFile(file.Path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		if i > 0 {
			buf.WriteString("\n---\n")
		}
		buf.Write(bytes.TrimSpace(body))
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func collectRuleFiles(args []string) ([]ruleFile, []skippedDir, error) {
	var files []ruleFile
	var skippedDirs []skippedDir
	seen := make(map[string]struct{})

	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, nil, fmt.Errorf("stat %s: %w", arg, err)
		}

		if info.IsDir() {
			listedFiles, listedSkipped, err := listRuleFiles(arg)
			if err != nil {
				return nil, nil, err
			}
			skippedDirs = append(skippedDirs, listedSkipped...)
			for _, file := range listedFiles {
				if _, ok := seen[file.Path]; ok {
					continue
				}
				seen[file.Path] = struct{}{}
				files = append(files, file)
			}
			continue
		}

		if !rulesource.IsRuleFileName(arg) {
			return nil, nil, fmt.Errorf("%s: not a YAML file (expected .yaml/.yml)", arg)
		}
		if _, ok := seen[arg]; ok {
			continue
		}
		seen[arg] = struct{}{}
		files = append(files, ruleFile{Path: arg, Name: filepath.Base(arg)})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	sort.Slice(skippedDirs, func(i, j int) bool {
		return skippedDirs[i].Path < skippedDirs[j].Path
	})
	return files, skippedDirs, nil
}

func collectRuleDirectoryFiles(rulesDir string) ([]ruleFile, []skippedDir, error) {
	info, err := os.Stat(rulesDir)
	if err != nil {
		return nil, nil, fmt.Errorf("stat rules directory %s: %w", rulesDir, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s: not a directory", rulesDir)
	}
	files, skippedDirs, err := listRuleFiles(rulesDir)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	sort.Slice(skippedDirs, func(i, j int) bool {
		return skippedDirs[i].Path < skippedDirs[j].Path
	})
	return files, skippedDirs, nil
}

type ruleFile struct {
	Path string
	Name string
}

type skippedDir struct {
	Path string
	Name string
}

func listRuleFiles(rulesDir string) ([]ruleFile, []skippedDir, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, nil, fmt.Errorf("read rules directory %s: %w", rulesDir, err)
	}

	var files []ruleFile
	var skippedDirs []skippedDir
	for _, entry := range entries {
		if entry.IsDir() {
			skippedDirs = append(skippedDirs, skippedDir{
				Path: filepath.Join(rulesDir, entry.Name()),
				Name: entry.Name(),
			})
			continue
		}
		if !rulesource.IsRuleFileName(entry.Name()) {
			continue
		}
		files = append(files, ruleFile{
			Path: filepath.Join(rulesDir, entry.Name()),
			Name: entry.Name(),
		})
	}
	return files, skippedDirs, nil
}
