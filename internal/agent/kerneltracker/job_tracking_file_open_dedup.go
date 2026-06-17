package kerneltracker

import "github.com/cicd-sensor/cicd-sensor/internal/jobevent"

const defaultFileOpenDedupKeyLimit = 4096

type fileOpenDedupKey struct {
	pid           int32
	startBoottime uint64
	execPath      string
	payload       fileOpenRecordPayload
}

func fileOpenDedupKeyForRecord(record jobevent.EventRecord) (fileOpenDedupKey, bool) {
	if record.Process.PID == 0 || record.Process.StartBoottime == 0 {
		return fileOpenDedupKey{}, false
	}
	if record.Tags["truncated"] == "path" {
		return fileOpenDedupKey{}, false
	}
	payload, ok := fileOpenPayloadFromRecord(record)
	if !ok {
		return fileOpenDedupKey{}, false
	}

	// The key includes rule-visible file_open payload fields. Timestamp and
	// event ID are intentionally excluded because they differ for every sample.
	return fileOpenDedupKey{
		pid:           record.Process.PID,
		startBoottime: record.Process.StartBoottime,
		execPath:      record.Process.ExecPath,
		payload:       payload,
	}, true
}

type fileOpenDedupState struct {
	limit int
	seen  map[fileOpenDedupKey]struct{}
	order []fileOpenDedupKey
	next  int
}

func newFileOpenDedupState(limit int) *fileOpenDedupState {
	return &fileOpenDedupState{
		limit: limit,
		seen:  make(map[fileOpenDedupKey]struct{}),
	}
}

func (s *fileOpenDedupState) contains(key fileOpenDedupKey) bool {
	if s == nil {
		return false
	}
	_, ok := s.seen[key]
	return ok
}

func (s *fileOpenDedupState) remember(key fileOpenDedupKey) {
	if s == nil || s.limit <= 0 {
		return
	}
	// This is FIFO, not LRU: a hot repeated key should not refresh itself and
	// keep evicting newer unique file_open keys.
	if _, ok := s.seen[key]; ok {
		return
	}
	// order is a fixed-size FIFO ring. Once full, next points at the oldest
	// slot; replacing that slot keeps membership bounded with O(1) work.
	if len(s.order) < s.limit {
		s.order = append(s.order, key)
	} else {
		oldest := s.order[s.next]
		delete(s.seen, oldest)
		s.order[s.next] = key
		s.next = (s.next + 1) % s.limit
	}
	s.seen[key] = struct{}{}
}
