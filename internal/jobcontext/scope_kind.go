package jobcontext

// ScopeKind identifies whether a scope belongs to the host or project side.
type ScopeKind string

const (
	ScopeKindHost    ScopeKind = "host"
	ScopeKindProject ScopeKind = "project"
)
