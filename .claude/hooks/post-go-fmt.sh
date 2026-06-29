#!/usr/bin/env bash
# PostToolUse — formats Go source files after every edit.

file=$(python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('file_path',''))" 2>/dev/null) || exit 0
[[ "$file" == *.go ]] && [[ -f "$file" ]] && gofmt -w "$file"
