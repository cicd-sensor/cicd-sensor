package managerclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

const (
	// DefaultIDTokenEarlyExpiry is how far before JWT exp the reuse source
	// refreshes. Matches the design's ReuseTokenSourceWithExpiry(60s).
	DefaultIDTokenEarlyExpiry = 60 * time.Second

	// DefaultMintHTTPTimeout bounds a single Actions ID token mint HTTP round
	// trip. Shared acquisition may also be canceled when the credential closes.
	DefaultMintHTTPTimeout = 10 * time.Second

	// TokenTypeHeader declares which credential kind Authorization carries.
	TokenTypeHeader       = "Cicd-Sensor-Token-Type"
	TokenTypeManagerToken = "manager-token"
	TokenTypeIDToken      = "id-token"
)

const (
	acquireKeyNormal = "normal"
	acquireKeyForce  = "force"
)

// ErrMintUnavailable is returned when the Actions ID token mint request fails.
// Callers map it to Connect Unavailable so Agent retry/backoff applies.
var ErrMintUnavailable = fmt.Errorf("id token mint unavailable")

// NewIDTokenMintHTTPClient returns an HTTP client for runner token minting.
// Redirects are rejected so a validated request_url cannot be widened via 3xx.
func NewIDTokenMintHTTPClient() *http.Client {
	client := NewConnectHTTPClient()
	client.Timeout = DefaultMintHTTPTimeout
	return client
}

// ActionsIDTokenSource mints GitHub Actions OIDC ID tokens via GET to the
// runner token service (same shape as cosign / actions/toolkit).
type ActionsIDTokenSource struct {
	RequestURL   string
	RequestToken string
	Audience     string
	HTTPClient   *http.Client

	mu sync.Mutex
}

// Token implements oauth2.TokenSource.
func (s *ActionsIDTokenSource) Token() (*oauth2.Token, error) {
	return s.TokenContext(context.Background())
}

// TokenContext mints an ID token using ctx for cancellation.
func (s *ActionsIDTokenSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: token source is nil", ErrMintUnavailable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	mintURL, err := buildMintURL(s.RequestURL, s.Audience)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMintUnavailable, err)
	}
	client := s.HTTPClient
	if client == nil {
		client = NewIDTokenMintHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mintURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMintUnavailable, err)
	}
	req.Header.Set("Authorization", "bearer "+s.RequestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMintUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read mint response: %v", ErrMintUnavailable, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: mint status %d", ErrMintUnavailable, resp.StatusCode)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode mint response: %v", ErrMintUnavailable, err)
	}
	if payload.Value == "" {
		return nil, fmt.Errorf("%w: empty id token", ErrMintUnavailable)
	}

	tok := &oauth2.Token{AccessToken: payload.Value, TokenType: "Bearer"}
	if exp, ok := jwtExpiry(payload.Value); ok {
		tok.Expiry = exp
	}
	return tok, nil
}

func buildMintURL(requestURL, audience string) (string, error) {
	if strings.TrimSpace(requestURL) == "" {
		return "", fmt.Errorf("request_url is required")
	}
	if strings.TrimSpace(audience) == "" {
		return "", fmt.Errorf("audience is required")
	}
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parse request_url: %w", err)
	}
	q := parsed.Query()
	q.Set("audience", audience)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func jwtExpiry(raw string) (time.Time, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Expiry int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, false
	}
	if claims.Expiry <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Expiry, 0), true
}

// NewReuseIDTokenSource wraps a mint source with early refresh (~60s) and
// serialized concurrent refreshes via oauth2.ReuseTokenSourceWithExpiry.
func NewReuseIDTokenSource(src oauth2.TokenSource) oauth2.TokenSource {
	return oauth2.ReuseTokenSourceWithExpiry(nil, src, DefaultIDTokenEarlyExpiry)
}

// CachedTokenSource wraps oauth2 reuse caching with shared acquisition.
// ForceRefresh remints and seeds the reuse source; Token continues through
// normal expiry checks instead of returning a pinned JWT forever.
type CachedTokenSource struct {
	mu          sync.Mutex
	acquireMu   sync.Mutex
	mint        oauth2.TokenSource
	reuse       oauth2.TokenSource
	flight      singleflight.Group
	opCtx       context.Context
	opCancel    context.CancelFunc
	mintTimeout time.Duration
	closed      bool
}

// NewCachedTokenSource wraps a mint source with reuse (~60s early expiry).
func NewCachedTokenSource(mint oauth2.TokenSource) *CachedTokenSource {
	return NewCachedTokenSourceWithTimeout(mint, DefaultMintHTTPTimeout)
}

// NewCachedTokenSourceWithTimeout is like NewCachedTokenSource but bounds
// shared mint acquisition with timeout (tests may pass a short duration).
// Non-positive timeout falls back to DefaultMintHTTPTimeout.
//
// The timeout applies to every remint, including the path where
// oauth2.ReuseTokenSource calls Token() without a caller context.
func NewCachedTokenSourceWithTimeout(mint oauth2.TokenSource, timeout time.Duration) *CachedTokenSource {
	if timeout <= 0 {
		timeout = DefaultMintHTTPTimeout
	}
	opCtx, cancel := context.WithCancel(context.Background())
	timed := &deadlineMintSource{inner: mint, parent: opCtx, timeout: timeout}
	return &CachedTokenSource{
		mint:        timed,
		reuse:       NewReuseIDTokenSource(timed),
		opCtx:       opCtx,
		opCancel:    cancel,
		mintTimeout: timeout,
	}
}

// deadlineMintSource bounds each mint with parent+timeout so remints triggered
// by oauth2.ReuseTokenSource.Token() (no caller context) still cannot stall
// past DefaultMintHTTPTimeout (or a test override).
type deadlineMintSource struct {
	inner   oauth2.TokenSource
	parent  context.Context
	timeout time.Duration
}

func (d *deadlineMintSource) Token() (*oauth2.Token, error) {
	return d.TokenContext(context.Background())
}

func (d *deadlineMintSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	parent := d.parent
	if parent == nil {
		parent = context.Background()
	}
	timeout := d.timeout
	if timeout <= 0 {
		timeout = DefaultMintHTTPTimeout
	}
	mintCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if ctx != nil {
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
	}
	return mintTokenContext(d.inner, mintCtx)
}

// Close cancels in-flight shared mint work. Call after the final Summary flush.
func (c *CachedTokenSource) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	cancel := c.opCancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ForceRefresh remints immediately and seeds the reuse cache with the fresh
// JWT. Used by project result before VM shutdown Summary.
func (c *CachedTokenSource) ForceRefresh(ctx context.Context) error {
	_, err := c.TokenContextForce(ctx)
	return err
}

// TokenContextForce is like TokenContext but always remints when possible.
func (c *CachedTokenSource) TokenContextForce(ctx context.Context) (*oauth2.Token, error) {
	return c.waitAcquire(ctx, true)
}

// Token implements oauth2.TokenSource.
func (c *CachedTokenSource) Token() (*oauth2.Token, error) {
	return c.TokenContext(context.Background())
}

// TokenContext returns a cached JWT when still valid, otherwise refreshes.
// Waiting honors ctx; the underlying shared mint uses a separate lifetime.
func (c *CachedTokenSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	return c.waitAcquire(ctx, false)
}

func (c *CachedTokenSource) waitAcquire(ctx context.Context, force bool) (*oauth2.Token, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: cached token source is nil", ErrMintUnavailable)
	}
	key := acquireKeyNormal
	if force {
		key = acquireKeyForce
	}
	ch := c.flight.DoChan(key, func() (any, error) {
		return c.executeAcquire(force)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("%w: acquisition interrupted", ErrMintUnavailable)
		}
		if res.Err != nil {
			return nil, res.Err
		}
		tok, ok := res.Val.(*oauth2.Token)
		if !ok || tok == nil {
			return nil, fmt.Errorf("%w: missing token", ErrMintUnavailable)
		}
		return tok, nil
	}
}

func (c *CachedTokenSource) executeAcquire(force bool) (*oauth2.Token, error) {
	c.acquireMu.Lock()
	defer c.acquireMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: token source closed", ErrMintUnavailable)
	}
	reuse := c.reuse
	mint := c.mint
	opCtx := c.opCtx
	c.mu.Unlock()

	if !force {
		// Cache hit returns immediately; cache miss remints through
		// deadlineMintSource (bounded). Do not mint again on failure.
		return reuse.Token()
	}

	timeout := c.mintTimeout
	if timeout <= 0 {
		timeout = DefaultMintHTTPTimeout
	}
	mintCtx, cancel := context.WithTimeout(opCtx, timeout)
	defer cancel()
	fresh, err := mintTokenContext(mint, mintCtx)
	if err != nil {
		// Force mint failed: keep serving a still-valid reuse cache entry.
		if tok, reuseErr := reuse.Token(); reuseErr == nil {
			return tok, nil
		}
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, fmt.Errorf("%w: token source closed", ErrMintUnavailable)
	}
	c.reuse = oauth2.ReuseTokenSourceWithExpiry(fresh, mint, DefaultIDTokenEarlyExpiry)
	return fresh, nil
}

func mintTokenContext(mint oauth2.TokenSource, ctx context.Context) (*oauth2.Token, error) {
	if mint == nil {
		return nil, fmt.Errorf("%w: mint source is nil", ErrMintUnavailable)
	}
	if ctxSrc, ok := mint.(interface {
		TokenContext(context.Context) (*oauth2.Token, error)
	}); ok {
		return ctxSrc.TokenContext(ctx)
	}
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", ErrMintUnavailable, ctx.Err())
	default:
		return mint.Token()
	}
}

// NewOIDCConnection builds a manager Connection that mints GitHub Actions ID
// tokens, reuses them with a 60s early refresh, and supports ForceRefresh for
// shutdown Summary.
func NewOIDCConnection(baseURL, requestURL, requestToken, audience string, httpClient *http.Client) Connection {
	if httpClient == nil {
		httpClient = NewIDTokenMintHTTPClient()
	}
	mint := &ActionsIDTokenSource{
		RequestURL:   requestURL,
		RequestToken: requestToken,
		Audience:     audience,
		HTTPClient:   httpClient,
	}
	cached := NewCachedTokenSource(mint)
	return Connection{
		BaseURL: baseURL,
		Auth:    IDTokenAuth(cached),
		Cached:  cached,
	}
}

// IsContextAcquisitionError reports caller cancellation/deadline errors from
// TokenContext that should not be mapped to Unavailable.
func IsContextAcquisitionError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
