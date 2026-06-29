#!/usr/bin/env bash
# PreToolUse — blocks edits to generated files.
# Exit 2 to block the tool call; exit 0 to allow.

file=$(python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('file_path',''))" 2>/dev/null) || exit 0
[[ -z "$file" ]] && exit 0

if echo "$file" | grep -qE '(internal/proto/.*\.pb(\.connect)?\.go$|internal/agent/bpf/generated/)'; then
  echo "BLOCKED: $file is generated — run 'make generate' to update it." >&2
  exit 2
fi
