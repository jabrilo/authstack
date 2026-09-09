package password

import (
	"context"

	"github.com/jabrilo/authstack"
)

type Verifier interface {
	ResolveIdendifierType(identifier string) (authstack.IdentifierType, error)
	AuthenticatePassword(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

type Config struct {
	Verifier           Verifier
	AllowedIdentifiers []authstack.IdentifierType
}
