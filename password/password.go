package password

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jabrilo/authstack"
)

type IdentifierType string

const (
	IdentifierEmail    IdentifierType = "email"
	IdentifierUsername IdentifierType = "username"
	IdentifierPhone    IdentifierType = "phone"
	IdentifierGeneric  IdentifierType = "generic"
)

const defaultEnumerationGuardSecret = "default-enumeration-guard-secret"

var (
	ErrIdentifierNotRecognized           = errors.New("password: identifier did not match any allowed type")
	ErrIdentifierNotAllowed              = errors.New("password: identifier type not allowed")
	ErrInvalidCredentials                = errors.New("password: invalid credentials")
	ErrNilPrincipal                      = errors.New("password: lookup returned nil principal with nil error")
	ErrHookRegistrarRequired             = errors.New("password: registrar hook is required")
	ErrHookLookupRequired                = errors.New("password: look up hook is required")
	ErrHookResolverRequired              = errors.New("password: identity resolver hook is required")
	ErrEmptyGardSecret                   = errors.New("password: enumeration guard secret must not be empty (leave unset to use the default)")
	ErrPasswordHasherRequired            = errors.New("password: password hasher is required")
	ErrRegistrationTransactionRequired   = errors.New("password: registration transaction is required")
	ErrPrincipalCallbackRequired         = errors.New("password: principal callback is required")
	ErrAuthenticationTransactionRequired = errors.New("password: authentication transaction is required")
)

type Registrar interface {
	RegisterPrincipal(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

type Verifier interface {
	AuthenticatePrincipal(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

type RegistrationTransaction interface {
	RegisterPrincipal(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

type AuthenticationTransaction interface {
	LookupPrincipal(ctx context.Context, identifier string) (*authstack.Principal, string, error)
}

type (
	RegistrarHook        func(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
	LookupHook           func(ctx context.Context, identifier string) (principal *authstack.Principal, hashedSecret string, err error)
	IdentityResolverHook func(ctx context.Context, identifier string) (IdentifierType, error)
	PrincipalCallback    func(ctx context.Context, principal *authstack.Principal) error
)

type PasswordAuth struct {
	cfg       Config
	resolve   IdentityResolverHook
	register  RegistrarHook
	lookup    LookupHook
	guardHash string
}

func New(register RegistrarHook, lookup LookupHook, cfg Config) (*PasswordAuth, error) {
	if register == nil {
		return nil, ErrHookRegistrarRequired
	}

	if lookup == nil {
		return nil, ErrHookLookupRequired
	}

	if cfg.IdentityResolver == nil {
		cfg.IdentityResolver = defaultIdentityResolver
	}

	if cfg.EnumerationGuardSecret == "" {
		return nil, ErrEmptyGardSecret
	}

	if cfg.Hasher == nil {
		return nil, ErrPasswordHasherRequired
	}

	guardHash, err := cfg.Hasher.Hash(context.Background(), cfg.EnumerationGuardSecret)
	if err != nil {
		return nil, fmt.Errorf("password: failed to precompute enumeration guard hash: %w", err)
	}

	return &PasswordAuth{
		cfg:       cfg,
		register:  register,
		lookup:    lookup,
		resolve:   cfg.IdentityResolver,
		guardHash: guardHash,
	}, nil
}

func defaultIdentityResolver(_ context.Context, _ string) (IdentifierType, error) {
	return IdentifierGeneric, nil
}

func (a *PasswordAuth) validateIdentifier(ctx context.Context, identifier string) error {
	t, err := a.resolve(ctx, identifier)
	if err != nil {
		return ErrIdentifierNotRecognized
	}

	if len(a.cfg.AllowedIdentifiers) > 0 && !slices.Contains(a.cfg.AllowedIdentifiers, t) {
		return ErrIdentifierNotAllowed
	}

	return nil
}

func (a *PasswordAuth) RegisterPrincipal(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	if a.resolve == nil {
		return nil, ErrHookResolverRequired
	}

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

func (a *PasswordAuth) RegisterPrincipalAnd(
	ctx context.Context,
	identifier string,
	secret string,
	tx RegistrationTransaction,
	callback PrincipalCallback,
) (*authstack.Principal, error) {
	if a.resolve == nil {
		return nil, ErrHookResolverRequired
	}

	if tx == nil {
		return nil, ErrRegistrationTransactionRequired
	}

	if callback == nil {
		return nil, ErrPrincipalCallbackRequired
	}

	if err := a.validateIdentifier(ctx, identifier); err != nil {
		return nil, err
	}

	hashedSecret, err := a.cfg.Hasher.Hash(ctx, secret)
	if err != nil {
		return nil, err
	}

	principal, err := tx.RegisterPrincipal(ctx, identifier, hashedSecret)
	if err != nil {
		return nil, err
	}

	if principal == nil {
		return nil, ErrNilPrincipal
	}

	principal.Provider = authstack.ProviderPassword

	if err := callback(ctx, principal); err != nil {
		return nil, err
	}

	return principal, nil
}

func (a *PasswordAuth) AuthenticatePrincipal(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	if a.resolve == nil {
		return nil, ErrHookResolverRequired
	}

	if a.lookup == nil {
		return nil, ErrHookLookupRequired
	}

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

func (a *PasswordAuth) AuthenticatePrincipalAnd(
	ctx context.Context,
	identifier string,
	secret string,
	tx AuthenticationTransaction,
	callback PrincipalCallback,
) (*authstack.Principal, error) {
	if a.resolve == nil {
		return nil, ErrHookResolverRequired
	}

	if tx == nil {
		return nil, ErrAuthenticationTransactionRequired
	}

	if callback == nil {
		return nil, ErrPrincipalCallbackRequired
	}

	if err := a.validateIdentifier(ctx, identifier); err != nil {
		return nil, err
	}

	principal, hashedSecret, err := tx.LookupPrincipal(ctx, identifier)
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

	if err := callback(ctx, principal); err != nil {
		return nil, err
	}

	return principal, nil
}

var _ Registrar = (*PasswordAuth)(nil)
var _ Verifier = (*PasswordAuth)(nil)
