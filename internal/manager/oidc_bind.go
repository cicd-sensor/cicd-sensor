package manager

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"connectrpc.com/connect"

	oidcauth "github.com/cicd-sensor/cicd-sensor/internal/managerauth/oidc"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

// jobIdentityCarrier is implemented by request messages that expose a
// JobIdentity for OIDC binding. Messages that do not expose JobIdentity
// reject OIDC principals.
type jobIdentityCarrier interface {
	GetJobIdentity() *managerv1beta1.JobIdentity
}

// ingestLogJobIdentity adapts IngestLogRequest, whose JobIdentity lives under
// the batch message rather than at the top level.
type ingestLogJobIdentity struct {
	msg *managerv1beta1.IngestLogRequest
}

func (a ingestLogJobIdentity) GetJobIdentity() *managerv1beta1.JobIdentity {
	if a.msg == nil || a.msg.GetBatch() == nil {
		return nil
	}
	return a.msg.GetBatch().GetJobIdentity()
}

// jobIdentityFromMessage returns the JobIdentity when the decoded message
// exposes one. exposes=false means a future RPC without JobIdentity.
func jobIdentityFromMessage(msg any) (identity *managerv1beta1.JobIdentity, exposes bool) {
	switch m := msg.(type) {
	case *managerv1beta1.FetchConfigRequest:
		return m.GetJobIdentity(), true
	case *managerv1beta1.IngestLogRequest:
		return ingestLogJobIdentity{msg: m}.GetJobIdentity(), true
	case jobIdentityCarrier:
		return m.GetJobIdentity(), true
	default:
		return nil, false
	}
}

// oidcJobIdentityInterceptor binds OIDC principals to JobIdentity.provider +
// project_path. Manager-token principals skip the check.
type oidcJobIdentityInterceptor struct {
	logger *slog.Logger
}

var _ connect.Interceptor = oidcJobIdentityInterceptor{}

func (i oidcJobIdentityInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.check(ctx, req.Any()); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (i oidcJobIdentityInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i oidcJobIdentityInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

func (i oidcJobIdentityInterceptor) check(ctx context.Context, msg any) error {
	principal, ok := principalFromContext(ctx)
	if !ok || !principal.isOIDC() {
		return nil
	}

	identity, exposes := jobIdentityFromMessage(msg)
	if !exposes {
		if i.logger != nil {
			i.logger.WarnContext(ctx, "manager_oidc_bind_rejected",
				"reason", "message_lacks_job_identity",
				"auth_kind", principal.Kind,
				"repository", principal.Repository,
			)
		}
		return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	}
	if identity == nil {
		if i.logger != nil {
			i.logger.WarnContext(ctx, "manager_oidc_bind_rejected",
				"reason", "missing_job_identity",
				"auth_kind", principal.Kind,
				"repository", principal.Repository,
			)
		}
		return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	}
	if identity.GetProvider() != "github" {
		if i.logger != nil {
			i.logger.WarnContext(ctx, "manager_oidc_bind_rejected",
				"reason", "provider_mismatch",
				"auth_kind", principal.Kind,
				"provider", identity.GetProvider(),
				"repository", principal.Repository,
			)
		}
		return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	}
	if oidcauth.NormalizeRepository(identity.GetProjectPath()) != oidcauth.NormalizeRepository(principal.Repository) {
		if i.logger != nil {
			i.logger.WarnContext(ctx, "manager_oidc_bind_rejected",
				"reason", "project_path_mismatch",
				"auth_kind", principal.Kind,
				"project_path", identity.GetProjectPath(),
				"repository", principal.Repository,
			)
		}
		return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	}
	applyVerifiedRepositoryIdentity(msg, principal.Repository)
	return nil
}

func applyVerifiedRepositoryIdentity(msg any, repository string) {
	if strings.TrimSpace(repository) == "" {
		return
	}
	switch m := msg.(type) {
	case *managerv1beta1.FetchConfigRequest:
		if m.GetJobIdentity() != nil {
			m.JobIdentity.ProjectPath = repository
		}
	case *managerv1beta1.IngestLogRequest:
		if m.GetBatch() != nil && m.GetBatch().GetJobIdentity() != nil {
			m.Batch.JobIdentity.ProjectPath = repository
		}
	}
}
