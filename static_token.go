package authstack

import "context"

type StaticTokenAuthenticator interface {
	AuthenticateStaticToken(ctx context.Context, token string) (*Principal, error)
}

type StaticTokenConfig struct {
	Header                   string
	FormatValidator          func(token string) error
	staticTokenAuthenticator StaticTokenAuthenticator
}
