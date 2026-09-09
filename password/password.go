package password

import (
	"context"

	"github.com/jabrilo/authstack"
)

type Verifier interface {
	AuthenticatePassword(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

type Config struct {
	Verifier            Verifier
	IdentityCustomizers map[authstack.IdentifierType]func(id string) bool
	AllowedIdentifiers  []authstack.IdentifierType
}
