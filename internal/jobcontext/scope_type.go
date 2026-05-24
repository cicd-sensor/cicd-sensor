package jobcontext

// ScopeType identifies whether a scope belongs to the host or project side.
type ScopeType string

const (
	ScopeTypeHost    ScopeType = "host"
	ScopeTypeProject ScopeType = "project"
)
