package managerclient

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"
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

func ConnectClientOptions(token string) []connect.ClientOption {
	return []connect.ClientOption{
		connect.WithReadMaxBytes(maxResponseBytes),
		withBearerToken(token),
	}
}

func withBearerToken(token string) connect.ClientOption {
	return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set(authorizationHeader, "Bearer "+token)
			return next(ctx, req)
		}
	}))
}
