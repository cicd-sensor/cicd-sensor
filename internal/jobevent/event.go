package jobevent

import (
	"time"
)

type Type string

const (
	ProcessExec       Type = "process_exec"
	NetworkConnect    Type = "network_connect"
	UnixSocketConnect Type = "unix_socket_connect"
	FileOpen          Type = "file_open"
	FileRemove        Type = "file_remove"
	FileMove          Type = "file_move"
	FileLink          Type = "file_link"
	Domain            Type = "domain"
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
	EventType Type              `json:"event_type"`
	Timestamp time.Time         `json:"timestamp"`
	Payload   map[string]any    `json:"payload,omitempty"`
	Process   ProcessSummary    `json:"process"`
	Tags      map[string]string `json:"-"`
}
