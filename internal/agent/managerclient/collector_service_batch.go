package managerclient

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
)

type LogBatch struct {
	Identity jobcontext.JobIdentity
	Scope    managerv1.Scope
	Kind     managerv1.LogKind
	Records  [][]byte
	FlushAt  time.Time
}

func BuildCollectorIngestLogBatch(batch LogBatch) (*managerv1.IngestLogBatch, error) {
	if len(batch.Records) == 0 {
		return nil, fmt.Errorf("collector ingest log batch has no records")
	}

	var jsonl bytes.Buffer
	for _, record := range batch.Records {
		if len(record) == 0 {
			continue
		}
		jsonl.Write(record)
		jsonl.WriteByte('\n')
	}
	if jsonl.Len() == 0 {
		return nil, fmt.Errorf("collector ingest log batch has no non-empty records")
	}

	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(jsonl.Bytes()); err != nil {
		_ = gzipWriter.Close()
		return nil, fmt.Errorf("gzip collector ingest log batch: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("close gzip collector ingest log batch: %w", err)
	}

	return &managerv1.IngestLogBatch{
		JobIdentity:     protoconv.ToProtoJobIdentity(batch.Identity),
		Scope:           batch.Scope,
		LogKind:         batch.Kind,
		CompressedJsonl: compressed.Bytes(),
		FlushAt:         timestamppb.New(batch.FlushAt.UTC()),
	}, nil
}
