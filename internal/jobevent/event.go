package jobevent

import (
	"time"
)

type Kind string

const (
	ProcessExec       Kind = "process_exec"
	NetworkConnect    Kind = "network_connect"
	UnixSocketConnect Kind = "unix_socket_connect"
	FileOpen          Kind = "file_open"
	FileRemove        Kind = "file_remove"
	FileMove          Kind = "file_move"
	FileLink          Kind = "file_link"
	Domain            Kind = "domain"
)

// AncestorProcess is one captured ancestor in newest-first lineage order.
type AncestorProcess struct {
	ExecPath string   `json:"exec_path,omitempty"`
	Argv     []string `json:"argv,omitempty"`
}

// ProcessSummary is a lightweight process snapshot captured at event time.
type ProcessSummary struct {
	PID           int32             `json:"pid,omitempty"`
	StartBoottime uint64            `json:"start_boottime,omitempty"`
	ExecPath      string            `json:"exec_path,omitempty"`
	Argv          []string          `json:"argv,omitempty"`
	Ancestors     []AncestorProcess `json:"ancestors,omitempty"`
}

// EventRecord is the per-job rule evaluation input emitted by KernelTracker.
type EventRecord struct {
	ID        string            `json:"id,omitempty"`
	EventKind Kind              `json:"event_kind"`
	Timestamp time.Time         `json:"timestamp"`
	Payload   map[string]any    `json:"payload,omitempty"`
	Process   ProcessSummary    `json:"process"`
	Tags      map[string]string `json:"-"`
}
