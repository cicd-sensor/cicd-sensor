---
description: Create a new Design Doc in work_docs/ for a large feature addition or substantial behavior change. Use when starting work that requires up-front design before implementation.
disable-model-invocation: true
allowed-tools: Read Write Bash(git log *) Bash(git diff *) Bash(grep *) Bash(find *)
---

Create a new Design Doc in `work_docs/` for the described change.

Steps:
1. Investigate first: read the relevant source files, docs, and recent commits before writing anything.
2. Derive a kebab-case slug from the task description (e.g., `work_docs/add-scope-isolation.md`).
3. Create the file with these sections (## headers):
   - Context and Scope
   - Goals
   - Non-Goals
   - Findings (investigation results, source links, measurements — facts only, no decisions)
   - Design (with a ### Implementation Notes subsection)
   - Alternatives Considered
   - Security Considerations
   - Cross-Cutting Concerns
   - Test Plan
   - Rollout and Progress (checklist of [ ] items)
4. In Design > Implementation Notes, answer these cicd-sensor-specific questions when relevant:
   - Which component owns the change (use the AGENTS.md component map)?
   - Does the change preserve Host scope / Project scope isolation?
   - What belongs in eBPF maps vs. userspace KernelTracker state?
   - Can the change affect event volume, queue pressure, or drop risk?
   - Which socket/endpoint is exposed, and what is the caller trust model?
   - Does the change alter CEL fields, RuleSet behavior, or event semantics?
   - Which runner environments are affected?
5. In Rollout and Progress, list decided / to-implement / to-verify items as checkboxes.

Rules:
- Keep facts (Findings) separate from decisions (Design).
- Do not start implementing until the doc exists and has been reviewed.
- Do not hide tradeoffs — if a rejected option is tempting, write why it was rejected.
