package password

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jabrilo/authstack"
)

type IdentifierType string

const defaultEnumerationGuardSecret = "default-enumeration-guard-secret"

const (
	IdentifierEmail    IdentifierType = "email"
	IdentifierUsername IdentifierType = "username"
	IdentifierPhone    IdentifierType = "phone"
	IdentifierGeneric  IdentifierType = "generic"
)

var (
	ErrIdentifierNotRecognized        = errors.New("password: identifier did not match any allowed type")
	ErrIdentifierNotAllowed           = errors.New("password: identifier type not allowed")
	ErrInvalidCredentials             = errors.New("password: invalid credentials")
	ErrNilPrincipal                   = errors.New("password: lookup returned nil principal with nil error")
	ErrHookRegistrarRequired          = errors.New("password: registrar hook is required")
	ErrHookLookupRequired             = errors.New("password: look up hook is required")
	ErrHookIdentifierResolverRequired = errors.New("password: identity resolver hook is required")
	ErrEmptyEnumerationGardSecret     = errors.New("password: enumeration guard secret must not be empty (leave unset to use the default)")
)

type Registrar interface {
	Register(ctx context.Context, identifier, hashedSecret string) (*authstack.Principal, error)
}

type Verifier interface {
	Authenticate(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

type RegistrarHook func(ctx context.Context, identifier, hashedSecret string) (*authstack.Principal, error)
type LookupHook func(ctx context.Context, identifier string) (principal *authstack.Principal, hashedSecret string, err error)
type IdentityResolverHook func(ctx context.Context, identifier string) (IdentifierType, error)

type Config struct {
	Hasher                 Hasher
	AllowedIdentifiers     []IdentifierType
	EnumerationGuardSecret string
}

type Authenticator struct {
	issuer    authstack.SessionIssuer
	cfg       Config
	resolve   IdentityResolverHook
	register  RegistrarHook
	lookup    LookupHook
	guardHash string
}

type Option func(*Config)

func WithHasher(h Hasher) Option {
	return func(c *Config) { c.Hasher = h }
}

func WithAllowedIdentifiers(types ...IdentifierType) Option {
	return func(c *Config) { c.AllowedIdentifiers = types }
}

func WithEnumerationGuardSecret(secret string) Option {
	return func(c *Config) { c.EnumerationGuardSecret = secret }
}

func NewConfig(opts ...Option) (Config, error) {
	cfg := Config{
		Hasher:                 DefaultHasher(),
		EnumerationGuardSecret: defaultEnumerationGuardSecret,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.EnumerationGuardSecret == "" {
		return Config{}, errors.New("password: enumeration guard secret must not be empty (leave unset to use the default)")
	}
	return cfg, nil
}

func New(
	si authstack.SessionIssuer,
	register RegistrarHook,
	lookup LookupHook,
	resolve IdentityResolverHook,
	cfg Config,
) (*Authenticator, error) {
	if si == nil {
		return nil, errors.New("password: session issuer is required")
	}

	if resolve == nil {
		return nil, ErrHookIdentifierResolverRequired
	}

	if register == nil {
		return nil, ErrHookRegistrarRequired
	}

	if lookup == nil {
		return nil, ErrHookLookupRequired
	}

	guardHash, err := cfg.Hasher.Hash(context.Background(), cfg.EnumerationGuardSecret)
	if err != nil {
		return nil, fmt.Errorf("password: failed to precompute enumeration guard hash: %w", err)
	}

	return &Authenticator{
		issuer:    si,
		cfg:       cfg,
		guardHash: guardHash,
	}, nil
}

func (a *Authenticator) validateIdentifier(ctx context.Context, identifier string) error {
	t, err := a.resolve(ctx, identifier)
	if err != nil {
		return ErrIdentifierNotRecognized
	}

	if len(a.cfg.AllowedIdentifiers) > 0 && !slices.Contains(a.cfg.AllowedIdentifiers, t) {
		return ErrIdentifierNotAllowed
	}

	return nil
}

func (a *Authenticator) Register(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	if a.register == nil {
		return nil, ErrHookRegistrarRequired
	}

	if err := a.validateIdentifier(ctx, identifier); err != nil {
		return nil, err
	}

	hashedSecret, err := a.cfg.Hasher.Hash(ctx, secret)
	if err != nil {
		return nil, err
	}

	principal, err := a.register(ctx, identifier, hashedSecret)
	if err != nil {
		return nil, err
	}

	if principal == nil {
		return nil, ErrNilPrincipal
	}

	principal.Provider = authstack.ProviderPassword

	return principal, nil
}

func (a *Authenticator) RegisterAndIssueSession(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	principal, err := a.Register(ctx, identifier, secret)
	if err != nil {
		return nil, err
	}

	if err = a.issuer.IssueSession(ctx, principal); err != nil {
		return nil, err
	}

	return principal, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	if err := a.validateIdentifier(ctx, identifier); err != nil {
		return nil, err
	}

	principal, hashedSecret, err := a.lookup(ctx, identifier)
	if err != nil {
		return nil, err
	}

	if principal == nil {
		_ = a.cfg.Hasher.Compare(ctx, a.guardHash, secret)
		return nil, ErrInvalidCredentials
	}

	if err = a.cfg.Hasher.Compare(ctx, hashedSecret, secret); err != nil {
		return nil, ErrInvalidCredentials
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
