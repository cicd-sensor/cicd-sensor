package managerclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/protoconv"
)

// ErrConfigCacheNotReady reports that no manager config has been fetched yet.
var ErrConfigCacheNotReady = errors.New("manager config cache not ready")

// DefaultHostConfigCacheRefreshInterval keeps host policy fresh without putting
// manager availability on the NRI CreateContainer hot path.
const DefaultHostConfigCacheRefreshInterval = time.Minute

type configFetcher interface {
	FetchConfig(context.Context, *managerv1beta1.FetchConfigRequest) (*FetchResult, error)
}

// HostConfigCache serves node-level host config from memory.
//
// Kubernetes NRI callbacks must not block on remote manager I/O. The Agent
// primes this cache before exposing Kubernetes listeners, and refresh keeps the
// last known-good config if the manager is temporarily unavailable.
type HostConfigCache struct {
	logger          *slog.Logger
	upstream        configFetcher
	request         *managerv1beta1.FetchConfigRequest
	refreshInterval time.Duration

	mu     sync.RWMutex
	result *FetchResult
}

// NewHostConfigCache creates a cache for one host-manager request shape.
func NewHostConfigCache(logger *slog.Logger, upstream configFetcher, request *managerv1beta1.FetchConfigRequest, refreshInterval time.Duration) (*HostConfigCache, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if upstream == nil {
		return nil, errors.New("host config cache upstream is nil")
	}
	if request == nil {
		return nil, errors.New("host config cache request is nil")
	}
	if refreshInterval <= 0 {
		refreshInterval = DefaultHostConfigCacheRefreshInterval
	}
	return &HostConfigCache{
		logger:          logger.With("component", "host_config_cache"),
		upstream:        upstream,
		request:         proto.Clone(request).(*managerv1beta1.FetchConfigRequest),
		refreshInterval: refreshInterval,
	}, nil
}

// Prime synchronously loads the first config. Agent startup calls this before
// Kubernetes NRI or runner sockets are made available.
func (c *HostConfigCache) Prime(ctx context.Context) error {
	if err := c.refresh(ctx); err != nil {
		return fmt.Errorf("prime host config cache: %w", err)
	}
	return nil
}

// Run periodically refreshes the cache until ctx is canceled.
func (c *HostConfigCache) Run(ctx context.Context) {
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.refresh(ctx); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				c.logger.WarnContext(ctx, "host_config_cache_refresh_failed", "error", err)
			}
		}
	}
}

// FetchConfig returns the cached host config and deliberately ignores the
// per-job request. Job-specific identity is applied later when rules are
// resolved and logs are emitted.
func (c *HostConfigCache) FetchConfig(_ context.Context, req *managerv1beta1.FetchConfigRequest) (*FetchResult, error) {
	if req == nil {
		return nil, errors.New("fetch config request is nil")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.result == nil {
		return nil, ErrConfigCacheNotReady
	}
	return cloneFetchResult(c.result), nil
}

func (c *HostConfigCache) refresh(ctx context.Context) error {
	result, err := c.upstream.FetchConfig(ctx, c.request)
	if err != nil {
		return err
	}
	if result == nil {
		return errors.New("manager config fetch returned nil result")
	}
	cloned := cloneFetchResult(result)
	c.mu.Lock()
	previousRevision := ""
	if c.result != nil {
		previousRevision = c.result.ConfigRevision
	}
	c.result = cloned
	c.mu.Unlock()
	attrs := []any{"config_revision", result.ConfigRevision, "rule_sources", len(result.RuleSources)}
	if previousRevision == result.ConfigRevision {
		c.logger.DebugContext(ctx, "host_config_cache_refreshed", attrs...)
	} else {
		c.logger.InfoContext(ctx, "host_config_cache_refreshed", attrs...)
	}
	return nil
}

func cloneFetchResult(in *FetchResult) *FetchResult {
	if in == nil {
		return nil
	}
	out := *in
	// FetchConfig hands rule data to each JobScopeState as caller-owned config.
	// Return an isolated copy so one job cannot alias the cached host policy or
	// another job's scope. This proto round-trip depends on protoconv carrying
	// every rule.* field; update protoconv whenever rule schema fields are added.
	out.RuleSources = protoconv.FromProtoRuleSources(protoconv.ToProtoRuleSources(in.RuleSources))
	if in.OutputSettings != nil {
		out.OutputSettings = proto.Clone(in.OutputSettings).(*managerv1beta1.OutputSettings)
	}
	return &out
}
