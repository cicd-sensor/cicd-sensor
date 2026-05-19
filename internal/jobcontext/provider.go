package jobcontext

// Provider identifies the CI/CD provider.
type Provider string

const (
	ProviderGitHub Provider = "github"
	ProviderGitLab Provider = "gitlab"
)
