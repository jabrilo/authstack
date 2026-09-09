package authstack

import "context"

type PasswordAuthenticator interface {
	AuthenticatePassword(ctx context.Context, identifier, secret string) (*Principal, error)
}

type PasswordConfig struct {
	Authenticator       PasswordAuthenticator
	IdentityCustomizers map[IdentifierType]func(id string) bool
	AllowedIdentifiers  []IdentifierType
}
