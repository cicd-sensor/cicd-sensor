---
paths:
  - "**/*.go"
  - "go.mod"
  - "go.sum"
---

# Go Code Rules

## Boundaries (non-negotiable)

Component ownership is the security model. Misplacing a field is a boundary bug, not a refactor.

- Before writing or moving code, identify which component owns the state, lifecycle, or interface you are touching. See `AGENTS.md` → **Agent components** for the map.
- Do not let responsibilities leak across components.
- Name fields and helpers so the owner is obvious at the call site.
- For `internal/agent/**` or `cmd/cicd-sensor/**`, read `docs/developer-guide/agent-ownership-boundaries.md` before adding fields to `Agent`, `JobRegistry`, `Job`, or `JobScopeState`. Host scope and project scope stay isolated.

## Baseline

- Go `1.26+` (`go.mod`). Prefer modern idioms.
- `context.Context` is the first parameter. Wrap errors with `%w`. Compare with `errors.Is` / `errors.As`.
- Avoid `init()` and `panic` outside `main` / tests. Rule, config, and CEL input must not crash the process — return an error.
- Use `log/slog`. No `fmt.Println` debug output.
- For file access with untrusted paths, use `os.OpenRoot` / `os.OpenInRoot`. Don't rely on `filepath.Clean` / prefix checks as the primary defense.
- Interfaces are defined on the consumer side.

## Security

### Unix socket auth

The control socket's filesystem mode is permissive (`controlSocketMode = 0o777` in `internal/agent/listener/listener.go`). Authorization is enforced through `SO_PEERCRED` peer credentials and cgroup tracking, not filesystem ACLs.

- **Hook / lifecycle endpoints** (GitHub `host/start`, `host/end`, `project/start`, `project/result`, `job/health`) read the peer PID from `SO_PEERCRED` and either **seed** Job cgroup tracking (host start: the hook process's cgroup becomes the Job's tracked-cgroups root) or **require** the peer to already belong to a tracked Job (`ErrPeerNotInJob` on miss). See `JobRegistry.FindJobForPeerPID` and siblings in `internal/agent/jobregistry/`, and `docs/developer-guide/agent-ownership-boundaries.md` for the ownership rules.
- **Agent-owner endpoints** (GitHub `staging/put`, GitLab `host/start`, GitLab `staging/put`) gate by `SO_PEERCRED` UID matching the agent process owner. See `requireRequestPeerUIDMatchesAgentOwner` in `internal/agent/listener/request_peer_linux.go`.

A new socket endpoint picks one of these gates explicitly. Do not trust callers just because the socket file exists.

### General

When a change accepts untrusted input and then performs a side effect — filesystem access, process exec, network call, command-line construction, HTML / template / log output that may be rendered downstream — the change is treated as security-sensitive and reviewed with that lens, not just functional review.

- Lean on trusted libraries — the Go standard library first, then well-maintained third-party packages — for crypto, encoding, parsing, escaping, auth, and path handling. Rolling a bespoke implementation in these areas is the default cause of security bugs.
- For file access with untrusted paths, prefer `os.OpenRoot` / `os.OpenInRoot` over hand-rolled `filepath.Clean` / prefix guards (also called out in Baseline).
- For HTML or template output, use the stdlib's contextual escaping (`html/template`, not `text/template`).
- Don't add ad-hoc validation as the primary defense when a stdlib safe API exists.
- Run the security review tooling before declaring such changes done:
  - Claude Code: `/security-review`.
  - Codex: invoke the `security-best-practices` skill.

## Style

- Keep changes small. Prefer concrete, simple, readable code. Don't generalize until needed.
- Don't add a helper, interface, or layer until a clear second use case or test boundary exists. A few lines of duplication beat a confusing abstraction.
- Don't split files or packages on planned future use. Split when the current responsibility actually divides.
- Package names stay short. Avoid `util`, `common`, `helper`.
- Check whether the standard library can replace a new helper or dependency before adding it.
- YAML uses `go.yaml.in/yaml/v4`.

## Comments

- Write Why, not a paraphrase of the code. Capture constraints, trade-offs, and known limits.
- Add godoc on exported symbols, starting with the symbol name.
- Field comments when unit or zero-value behavior matters.
- `TODO` / `FIXME` / `HACK` include the reason.

## Tooling

- `gofmt`, `go vet`, `go test` (`-race` for concurrency).
- Prefer `go fix` for mechanical modernization. Use `staticcheck` when available.

## Modern APIs (reference)

Reach for these when they fit, but Style above wins if they conflict.

### `slices`

- Search: `Contains`, `ContainsFunc`, `Index`, `IndexFunc`, `BinarySearch`
- Sort: `Sort`, `SortFunc`, `SortStableFunc`, `IsSorted`
- Build: `Clone`, `Concat`, `Compact`, `Reverse`, `Delete`, `Insert`
- Compare: `Equal`, `EqualFunc`
- Iterator-shaped: `All`, `Values`, `Backward`, `Sorted`, `SortedFunc`, `Chunk`, `Collect`, `AppendSeq`

### `maps`

- `Keys`, `Values`, `Clone`, `Copy`, `Equal`, `DeleteFunc`
- Iterator-shaped: `All`, `Collect`, `Insert`

### Comparison

- `cmp.Compare`, `cmp.Less` — replace hand-rolled comparators.
- `cmp.Or(a, b, ...)` — first non-zero value; replace fallback if-chains.
- `min(a, b)`, `max(a, b)`, `clear(m | s)` builtins.

### Sync

- `sync.OnceFunc` / `OnceValue` / `OnceValues` instead of hand-written `sync.Once` patterns.
- `wg.Go(fn)` on `sync.WaitGroup` instead of `wg.Add(1); go func(){ defer wg.Done(); ... }()`.

### Iteration

- `for i := range N` for integer loops.
- Range-over-function (`iter.Seq`, `iter.Seq2`) is what drives the iterator-shaped APIs above. Author your own iterators when a function naturally produces a stream.

### Time

- Don't drain a `time.Timer` channel after `Stop()`. Modules at `go 1.23+` have unbuffered timer channels; draining is wrong.

## Testing

See `.claude/rules/20-testing.md` for testing rules and the required output format.
