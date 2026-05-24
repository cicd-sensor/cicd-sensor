package sink

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// objectKeySuffix returns a short random suffix for one object-storage write.
// It sits just before .json.gz so flush_at remains the leading sort key.
func objectKeySuffix() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate object key suffix: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// objectKey keeps object-storage naming in sink code. A random suffix prevents
// same-flush batches from overwriting each other while preserving sort prefix.
func objectKey(batch IngestLogBatch) (string, error) {
	identityKey, err := batch.Identity.FilenameKey()
	if err != nil {
		return "", err
	}
	suffix, err := objectKeySuffix()
	if err != nil {
		return "", err
	}
	receivedAt := batch.ReceivedAt.UTC()
	return fmt.Sprintf("%s/dt=%s/hour=%02d/%s_%s_%s_%s.json.gz",
		batch.LogType,
		receivedAt.Format("2006-01-02"),
		receivedAt.Hour(),
		formatFlushAt(batch.FlushAt),
		identityKey,
		batch.Scope,
		suffix,
	), nil
}

// formatFlushAt renders the agent flush timestamp for object keys and
// provider metadata. Millisecond precision keeps keys stable and sortable.
func formatFlushAt(ts time.Time) string {
	t := ts.UTC()
	ms := t.Nanosecond() / 1_000_000
	return t.Format("20060102150405") + fmt.Sprintf("%03d", ms)
}
