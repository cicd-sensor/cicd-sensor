package jobcontext

// GitHubStagingPutRequest is shared by the dockerd proxy and listener.
type GitHubStagingPutRequest struct {
	Basename string `json:"basename"`
	PeerPID  int32  `json:"peer_pid"`
}

// GitHubK8sStagingPutRequest is sent by the host-side NRI observer. NRI runs
// outside the job process tree, so it must provide identity explicitly.
type GitHubK8sStagingPutRequest struct {
	Basename    string      `json:"basename"`
	JobIdentity JobIdentity `json:"job_identity"`
}

// GitLabStagingPutRequest lets the proxy send peer PID, labels identity, and
// metadata; the agent chooses peer PID first, then labels identity when needed.
type GitLabStagingPutRequest struct {
	Basename    string       `json:"basename"`
	PeerPID     int32        `json:"peer_pid,omitempty"`
	JobIdentity *JobIdentity `json:"job_identity,omitempty"`
	Metadata    JobMetadata  `json:"metadata,omitempty"`
}

// GitLabK8sStagingPutRequest is sent by the host-side NRI observer. The
// listener owns lazy Job creation so NRI only posts one staging request.
type GitLabK8sStagingPutRequest struct {
	Basename    string      `json:"basename"`
	JobIdentity JobIdentity `json:"job_identity"`
	Metadata    JobMetadata `json:"metadata,omitempty"`
}

// GitLabHostStartRequest is the explicit GitLab host-start compatibility path.
type GitLabHostStartRequest struct {
	JobIdentity
	Metadata JobMetadata `json:"metadata,omitempty"`
}
