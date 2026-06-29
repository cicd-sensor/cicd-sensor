@AGENTS.md

## What lives in skills — not here

These load on demand and cost nothing until invoked:

| Skill | Purpose |
| --- | --- |
| `/design-doc` | Start a Design Doc in `work_docs/` for a large change |
| `/ticket <N>` | Load GitHub issue #N into context |
| `explorer` subagent | Read-only codebase exploration without consuming this window |
| `onboarder` subagent | Propose the next step based on current branch and git state |

Area-specific context (which component, what not to edit) is injected by `.claude/hooks/session-start.sh` before turn 1.
