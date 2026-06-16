# Design Doc Rules

Use a Design Doc for large feature additions or substantial behavior changes before implementation. Keep it useful as a local working document, not a ceremony.

The format should roughly follow a Google-style design doc, with extra implementation guidance for AI agents and an explicit progress checklist:

- **Context and Scope**: what problem this addresses, where in the system it lives, and what is out of scope.
- **Goals**: concrete outcomes the implementation must achieve.
- **Non-Goals**: adjacent work that must not be pulled into this change.
- **Findings**: investigation results, measurements, source links, runtime observations, or constraints that justify the design.
- **Design**: the proposed behavior, ownership boundaries, data flow, state lifecycle, and implementation notes as needed.
- **Alternatives Considered**: plausible options and why they were rejected.
- **Security Considerations**: trust boundaries, attacker-controlled inputs, privilege changes, socket / filesystem / network exposure, sensitive data handling, and what must not be weakened.
- **Cross-Cutting Concerns**: correctness, performance, memory, observability, compatibility, rollout, and operations when relevant.
- **Test Plan**: unit, integration, manual, migration, and regression checks.
- **Rollout and Progress**: checklist of decided, implemented, verified, and follow-up items. Use this section to track progress while the local implementation work is ongoing.

## AI-oriented implementation detail

For this repo, the **Design** section should include more implementation detail than a typical high-level design doc. Add a `### Implementation Notes` subsection under `## Design` when the change is large enough that an AI coding agent would otherwise need to guess.

In `Design > Implementation Notes`, include these details when they are known:

- Which component owns the change. Use the ownership map in `AGENTS.md`.
- Which package / file / function boundaries are expected to change.
- What state is introduced, who owns its lifecycle, and when it is cleaned up.
- What library, standard API, protocol, socket, hook, or runtime mechanism should be used.
- What must not be touched.
- The intended control flow or data flow, preferably with a small text diagram.
- Important edge cases and failure behavior.
- Security-sensitive assumptions, including what an attacker can control and what signal must not be hidden.
- Required comments when the code needs to preserve a non-obvious constraint.
- Concrete tests to add or update, including integration / BPF / Kubernetes smoke tests when relevant.

Implementation Notes should not force a line-by-line plan. They should make ownership, boundaries, and invariants clear enough that the implementation can be written without re-litigating the design.

## cicd-sensor-specific checks

When relevant, explicitly answer these project-specific questions:

- **Job boundary**: what identifies the CI/CD Job, and which cgroup / container / runner signal is authoritative?
- **Scope ownership**: does the change preserve Host scope and Project scope isolation, including separate rules, outputs, and manager config ownership?
- **Kernel boundary**: what belongs in eBPF maps or hooks, and what belongs in userspace `KernelTracker` state?
- **Kernel support**: when touching eBPF, state the required kernel versions, configs, attach points, helpers / kfuncs, and fallback or unsupported behavior.
- **Hot path behavior**: can the change increase event volume, queue pressure, memory use, or drop risk, and how is that visible?
- **Socket and caller trust**: which socket / endpoint is exposed to which process, how is the caller identified, and is the failure mode fail-open or fail-closed?
- **Kubernetes runtime**: if NRI, ARC hooks, containerd, or cgroups are involved, state the node requirements, timing constraints, and same-node assumptions.
- **Rule and event schema**: does the change alter CEL fields, RuleSet behavior, baseline rules, or user-facing event semantics?
- **Evidence outputs**: which Summary, Detection, Runtime Event, report, or attestation outputs change?
- **Deployment surface**: which runner environments are affected: GitHub-hosted, installed machine runner, GitHub ARC, GitLab Runner, or Kubernetes executor?

## Working Rules

- Keep facts and measurements separate from decisions.
- Prefer concrete names over placeholders when the component or API is already known.
- Do not hide tradeoffs. If a rejected option is tempting, write why it is rejected.
- Update the progress checklist as work advances.
