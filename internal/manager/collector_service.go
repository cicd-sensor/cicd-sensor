package manager

import (
	"context"
	"errors"
	"fmt"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
)

type collectorServiceHandler struct {
	server *Server
}

func newCollectorServiceHandler(s *Server) managerv1connect.CollectorServiceHandler {
	return &collectorServiceHandler{server: s}
}

// IngestLog validates one compressed batch, keeps the payload opaque, and
// writes the same bytes to every configured sink.
func (h *collectorServiceHandler) IngestLog(ctx context.Context, req *connect.Request[managerv1.IngestLogRequest]) (*connect.Response[managerv1.IngestLogResponse], error) {
	msg := req.Msg.GetBatch()
	if msg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("ingest log batch is required"))
	}
	if err := protovalidate.Validate(req.Msg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid request: %w", err))
	}
	// The manager is a transport boundary here: it only verifies gzip shape,
	// then stores the exact bytes the agent sent.
	if err := validateCompressedJSONL(msg.CompressedJsonl); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Identity, scope, log type, and flush time become sink routing data.
	// Reject unstable values before any sink observes the batch.
	identity := protoconv.FromProtoJobIdentity(msg.JobIdentity)
	if err := identity.Validate(); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid job identity: %w", err))
	}
	if err := validateFlushAt(msg.FlushAt); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	logType, err := outputLogType(msg.LogType)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	scope, err := outputScope(msg.Scope)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	batch := sink.IngestLogBatch{
		LogType:    logType,
		Identity:   identity,
		Scope:      scope,
		FlushAt:    msg.FlushAt.AsTime().UTC(),
		ReceivedAt: h.server.now().UTC(),
		Body:       msg.CompressedJsonl,
	}

	if h.server.logger != nil {
		h.server.logger.InfoContext(ctx, "manager_ingest_received_batch",
			"log_type", batch.LogType,
			"scope", scope,
			"flush_at", batch.FlushAt,
			"bytes", len(batch.Body),
		)
	}

	router := h.server.outputRouter
	if router == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errNoCollectorSinks)
	}

	if err := router.Write(ctx, batch); err != nil {
		if errors.Is(err, sink.ErrThrottled) {
			return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("collector output throttled: %w", err))
		}
		if errors.Is(err, errNoCollectorSinks) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("collector output failed: %w", err))
	}

	return connect.NewResponse(&managerv1.IngestLogResponse{
		ReceivedBatches: 1,
		BytesWritten:    uint64(len(batch.Body)),
	}), nil
}

// validateCompressedJSONL checks only gzip framing. The manager deliberately
// avoids parsing JSONL so one sink failure or schema drift cannot change bytes.
func validateCompressedJSONL(body []byte) error {
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		return errors.New("compressed_jsonl must be gzip-compressed JSONL")
	}
	return nil
}

// validateFlushAt rejects nil and out-of-range timestamps. Calendar shape is
// enforced by the proto type; this keeps sink routing keys stable.
func validateFlushAt(ts *timestamppb.Timestamp) error {
	if ts == nil {
		return errors.New("flush_at is required")
	}
	if err := ts.CheckValid(); err != nil {
		return fmt.Errorf("flush_at invalid: %w", err)
	}
	t := ts.AsTime()
	if t.Year() < 2000 || t.Year() > 2999 {
		return fmt.Errorf("flush_at year must be between 2000 and 2999")
	}
	return nil
}

// outputLogType maps the wire enum to the stable log type used by sinks.
func outputLogType(logType managerv1.LogType) (logtype.LogType, error) {
	switch logType {
	case managerv1.LogType_LOG_TYPE_DETECTION:
		return logtype.Detection, nil
	case managerv1.LogType_LOG_TYPE_RUNTIME_EVENT:
		return logtype.RuntimeEvent, nil
	case managerv1.LogType_LOG_TYPE_SUMMARY:
		return logtype.Summary, nil
	default:
		return "", fmt.Errorf("unsupported log_type: %s", logType.String())
	}
}

// outputScope rejects unspecified scope before sinks build provider-specific
// routing data from it.
func outputScope(scope managerv1.Scope) (sink.Scope, error) {
	switch scope {
	case managerv1.Scope_SCOPE_HOST:
		return sink.ScopeHost, nil
	case managerv1.Scope_SCOPE_PROJECT:
		return sink.ScopeProject, nil
	default:
		return "", fmt.Errorf("unsupported scope: %s", scope.String())
	}
}
