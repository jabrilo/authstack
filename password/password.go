package password

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jabrilo/authstack"
	"golang.org/x/crypto/bcrypt"
)

type IdentifierType string

const (
	IdentifierEmail    IdentifierType = "email"
	IdentifierUsername IdentifierType = "username"
	IdentifierPhone    IdentifierType = "phone"
	IdentifierGeneric  IdentifierType = "generic"
)

var (
	ErrIdentifierNotRecognized = errors.New("password: identifier did not match any allowed type")
	ErrIdentifierNotAllowed    = errors.New("password: identifier type not allowed")
	ErrInvalidCredentials      = errors.New("password: invalid credentials")
	ErrNilPrincipal            = errors.New("password: verifier returned nil principal with nil error")
	ErrRegistrarRequired       = errors.New("password: registrar is required for principal creation")
	ErrMismatchedSecret        = errors.New("password: hashed secret does not match provided secret")
)

type Registrar interface {
	Register(ctx context.Context, identifier, hashedSecret string) (*authstack.Principal, error)
}

type Verifier interface {
	ResolveIdentifierType(identifier string) (IdentifierType, error)
	AuthenticatePassword(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

type Hasher interface {
	Hash(ctx context.Context, secret string) (string, error)
	Compare(ctx context.Context, hashedSecret, secret string) error
}

type BcryptHasher struct {
	Cost int
}

func DefaultHasher() BcryptHasher {
	return BcryptHasher{Cost: bcrypt.DefaultCost}
}

func (h BcryptHasher) Hash(ctx context.Context, secret string) (string, error) {
	cost := h.Cost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
	if err != nil {
		return "", fmt.Errorf("failed to generate bcrypt hash: %w", err)
	}

	return string(bytes), nil
}

func (h BcryptHasher) Compare(ctx context.Context, hashedSecret, secret string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(secret))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrMismatchedSecret
		}
		return fmt.Errorf("failed to compare hash: %w", err)
	}
	return nil
}

type Config struct {
	Registrar          Registrar
	Verifier           Verifier
	Hasher             Hasher
	AllowedIdentifiers []IdentifierType
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

	if c.Hasher == nil {
		c.Hasher = DefaultHasher()
	}

	return &Authenticator{
		issuer: si,
		cfg:    c,
	}, nil
}

func (a *Authenticator) validateIdentifier(identifier string) error {
	t, err := a.cfg.Verifier.ResolveIdentifierType(identifier)
	if err != nil {
		return ErrIdentifierNotRecognized
	}

	if len(a.cfg.AllowedIdentifiers) > 0 && !slices.Contains(a.cfg.AllowedIdentifiers, t) {
		return ErrIdentifierNotAllowed
	}

	return nil
}

func (a *Authenticator) Create(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	if a.cfg.Registrar == nil {
		return nil, ErrRegistrarRequired
	}

	if err := a.validateIdentifier(identifier); err != nil {
		return nil, err
	}

	hashedSecret, err := a.cfg.Hasher.Hash(ctx, secret)
	if err != nil {
		return nil, err
	}

	principal, err := a.cfg.Registrar.Register(ctx, identifier, hashedSecret)
	if err != nil {
		return nil, err
	}

	if principal == nil {
		return nil, ErrNilPrincipal
	}

	principal.Provider = authstack.ProviderPassword

	return principal, nil
}

func (a *Authenticator) CreateAndIssueSession(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	principal, err := a.Create(ctx, identifier, secret)
	if err != nil {
		return nil, err
	}

	if err = a.issuer.IssueSession(ctx, principal); err != nil {
		return nil, err
	}

	return principal, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	if err := a.validateIdentifier(identifier); err != nil {
		return nil, err
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
