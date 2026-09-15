package static_token

import (
	"context"

	"github.com/jabrilo/authstack"
)

type StaticTokenAuthenticator interface {
	AuthenticateStaticToken(ctx context.Context, token string) (*authstack.Principal, error)
}

type StaticTokenConfig struct {
	Header                   string
	FormatValidator          func(token string) error
	staticTokenAuthenticator StaticTokenAuthenticator
}
