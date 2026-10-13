package managerclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/oauth2"
)

const maxResponseBytes = 64 * 1024 * 1024

const authorizationHeader = "Authorization"

func NewConnectHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ConnectClientOptions builds Connect options for a static manager-token.
// It always sends Cicd-Sensor-Token-Type: manager-token.
func ConnectClientOptions(token string) []connect.ClientOption {
	return ConnectClientOptionsWithAuth(StaticTokenAuth(token))
}

// ClientAuth describes how manager Connect clients obtain credentials.
type ClientAuth struct {
	TokenType   string
	Token       string
	TokenSource oauth2.TokenSource
}

// StaticTokenAuth is the default manager-token path.
func StaticTokenAuth(token string) ClientAuth {
	return ClientAuth{
		TokenType: TokenTypeManagerToken,
		Token:     token,
	}
}

// IDTokenAuth uses a refreshing OIDC TokenSource.
func IDTokenAuth(src oauth2.TokenSource) ClientAuth {
	return ClientAuth{
		TokenType:   TokenTypeIDToken,
		TokenSource: src,
	}
}

// ConnectClientOptionsWithAuth sets Authorization and Cicd-Sensor-Token-Type.
func ConnectClientOptionsWithAuth(auth ClientAuth) []connect.ClientOption {
	tokenType := auth.TokenType
	if tokenType == "" {
		tokenType = TokenTypeManagerToken
	}
	return []connect.ClientOption{
		connect.WithReadMaxBytes(maxResponseBytes),
		withClientAuth(auth.Token, auth.TokenSource, tokenType),
	}
}

func withClientAuth(staticToken string, src oauth2.TokenSource, tokenType string) connect.ClientOption {
	return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			token := staticToken
			if src != nil {
				tok, err := tokenFromSource(ctx, src)
				if err != nil {
					if errors.Is(err, context.Canceled) {
						return nil, connect.NewError(connect.CodeCanceled, err)
					}
					if errors.Is(err, context.DeadlineExceeded) {
						return nil, connect.NewError(connect.CodeDeadlineExceeded, err)
					}
					return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("%w", err))
				}
				token = tok.AccessToken
			}
			if token == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("manager credential is empty"))
			}
			req.Header().Set(authorizationHeader, "Bearer "+token)
			req.Header().Set(TokenTypeHeader, tokenType)
			return next(ctx, req)
		}
	}))
}

func tokenFromSource(ctx context.Context, src oauth2.TokenSource) (*oauth2.Token, error) {
	if ctxSrc, ok := src.(interface {
		TokenContext(context.Context) (*oauth2.Token, error)
	}); ok {
		return ctxSrc.TokenContext(ctx)
	}
	return src.Token()
}
