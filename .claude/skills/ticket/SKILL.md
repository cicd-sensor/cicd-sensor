---
description: Load a GitHub issue into context by issue number. Use when starting work on a ticket, need to understand requirements or acceptance criteria, or want context before implementing.
disable-model-invocation: true
argument-hint: <issue-number>
allowed-tools: Bash(gh issue view *) Bash(gh issue list *)
---

## Issue #$ARGUMENTS

!`gh issue view $ARGUMENTS --json title,body,labels,assignees,state,comments 2>/dev/null || echo "Issue #$ARGUMENTS not found — check 'gh auth status'"`

## Instructions

Based on the issue above:
1. Summarize what needs to be done in 2–3 bullets.
2. Identify which component(s) own the affected code using the AGENTS.md component map.
3. Suggest a branch name: `feat/issue-$ARGUMENTS-<kebab-slug>`.
4. Flag if the scope is large enough to warrant `/design-doc` before implementation.
