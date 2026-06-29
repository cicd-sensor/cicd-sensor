#!/usr/bin/env bash
# SessionStart hook: stdout is injected as context before turn 1.

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
rel=$(python3 -c "import os,sys; r=os.path.relpath(sys.argv[1],sys.argv[2]); print('.' if r=='' else r)" "$PWD" "$repo_root" 2>/dev/null || echo ".")

case "$rel" in
  internal/agent*|cmd/cicd-sensor|cmd/cicd-sensor/*)
    echo "Context: Agent subsystem (${rel})."
    echo "JobRegistry / Job / Scope / KernelTracker ownership boundaries are the security model."
    echo "Read docs/developer-guide/agent-ownership-boundaries.md before adding fields to Agent, Job, JobRegistry, or JobScopeState."
    echo "Generated BPF files: internal/agent/bpf/generated/ — run 'make generate', never edit directly."
    ;;
  internal/rule*|rules/*)
    echo "Context: Rule engine subsystem (${rel})."
    echo "CEL surface is intentionally narrow — widen only after a docs/ update."
    echo "Run 'make rules-validate' after changing rule YAML. See .claude/rules/30-cel-rules.md."
    ;;
  internal/manager*|cmd/cicd-sensor-manager*)
    echo "Context: Manager subsystem (${rel})."
    echo "Boundary: config delivery and log output routing. Does not own Jobs or KernelTracker state."
    echo "See docs/developer-guide/manager.md."
    ;;
  internal/ctl*|cmd/cicd-sensorctl*)
    echo "Context: CTL subsystem (${rel})."
    echo "Owns report and attestation generation. No job lifecycle logic here."
    ;;
  proto/*)
    echo "Context: proto/ — protobuf schema."
    echo "After changing .proto files run 'make generate'. Never edit generated *.pb.go or *.pb.connect.go directly."
    ;;
  docs/*)
    echo "Context: docs/ — design source of truth published at cicd-sensor.github.io."
    echo "Changes must reflect actual implemented behavior, not aspirational design."
    ;;
  ".")
    echo "Context: cicd-sensor repo root."
    echo "Run 'make check' before committing (generate + test + rules-validate + diff-check)."
    echo "Use the 'explorer' subagent to explore a subsystem without loading file bodies into this window."
    ;;
  *)
    echo "Context: cicd-sensor — ${rel}. Run 'make check' before committing."
    ;;
esac
