package password

import (
	"context"

	"github.com/jabrilo/authstack"
)

type Authenticator interface {
	AuthenticatePassword(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

type Config struct {
	Authenticator       Authenticator
	IdentityCustomizers map[authstack.IdentifierType]func(id string) bool
	AllowedIdentifiers  []authstack.IdentifierType
}
