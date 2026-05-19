package jobcontext

// GitHubStagingPutRequest is shared by the dockerd proxy and listener.
type GitHubStagingPutRequest struct {
	Basename string `json:"basename"`
	PeerPID  int32  `json:"peer_pid"`
}

// GitLabStagingPutRequest lets the proxy send both evidence sources; the agent
// chooses peer PID first, then labels identity when needed.
type GitLabStagingPutRequest struct {
	Basename    string       `json:"basename"`
	PeerPID     int32        `json:"peer_pid,omitempty"`
	JobIdentity *JobIdentity `json:"job_identity,omitempty"`
}

// GitLabHostStartRequest is the proxy lazy-create payload.
type GitLabHostStartRequest struct {
	JobIdentity
	Metadata JobMetadata `json:"metadata,omitempty"`
}
