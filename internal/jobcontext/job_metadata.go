package jobcontext

// JobMetadata carries optional non-identity context attached to a Job.
// JobIdentity owns attribution; metadata is for logs, reports, and search.
type JobMetadata struct {
	CommitSHA   string `json:"commit_sha,omitempty"`
	Branch      string `json:"branch,omitempty"`
	Trigger     string `json:"trigger,omitempty"`
	Workflow    string `json:"workflow,omitempty"`
	WorkflowRef string `json:"workflow_ref,omitempty"`
	WorkflowSHA string `json:"workflow_sha,omitempty"`
	Actor       string `json:"actor,omitempty"`
}
