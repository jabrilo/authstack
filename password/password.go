package password

import (
	"context"
	"errors"
	"slices"

	"github.com/jabrilo/authstack"
)

var (
	ErrIdentifierNotRecognized = errors.New("password: identifier did not match any allowed type")
	ErrIdentifierNotAllowed    = errors.New("password: identifier type not allowed")
	ErrInvalidCredentials      = errors.New("password: invalid credentials")
	ErrNilPrincipal            = errors.New("password: verifier returned nil principal with nil error")
)

type Verifier interface {
	ResolveIdendifierType(identifier string) (authstack.IdentifierType, error)
	AuthenticatePassword(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

type Config struct {
	Verifier           Verifier
	AllowedIdentifiers []authstack.IdentifierType
}

type Authenticator struct {
	issuer authstack.SessionIssuer
	cfg    Config
}

func New(si authstack.SessionIssuer, c Config) (*Authenticator, error) {
	if si == nil {
		return nil, errors.New("password: session issuer is required")
	}

	if c.Verifier == nil {
		return nil, errors.New("password: verifier is required")
	}

	return &Authenticator{
		issuer: si,
		cfg:    c,
	}, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	t, err := a.cfg.Verifier.ResolveIdendifierType(identifier)
	if err != nil {
		return nil, ErrIdentifierNotRecognized
	}

	if len(a.cfg.AllowedIdentifiers) > 0 && !slices.Contains(a.cfg.AllowedIdentifiers, t) {
		return nil, ErrIdentifierNotAllowed
	}

	principal, err := a.cfg.Verifier.AuthenticatePassword(ctx, identifier, secret)
	if err != nil {
		return nil, err
	}

	if principal == nil {
		return nil, ErrNilPrincipal
	}

	principal.Provider = authstack.ProviderPassword

	return principal, nil
}

func (a *Authenticator) AuthenticateAndIssueSession(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	principal, err := a.Authenticate(ctx, identifier, secret)
	if err != nil {
		return nil, err
	}

	if err = a.issuer.IssueSession(ctx, principal); err != nil {
		return nil, err
	}

	return principal, nil
}
