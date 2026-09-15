package password_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jabrilo/authstack"
	"github.com/jabrilo/authstack/password"
)

type registrationTransaction struct {
	principal    *authstack.Principal
	hashedSecret string
}

func (tx *registrationTransaction) RegisterPrincipal(_ context.Context, _ string, hashedSecret string) (*authstack.Principal, error) {
	tx.hashedSecret = hashedSecret
	return tx.principal, nil
}

type authenticationTransaction struct {
	principal    *authstack.Principal
	hashedSecret string
}

func (tx *authenticationTransaction) LookupPrincipal(context.Context, string) (*authstack.Principal, string, error) {
	return tx.principal, tx.hashedSecret, nil
}

func TestPasswordAuth_AuthenticatePrincipal(t *testing.T) {
	cfg := password.NewConfig()
	auth, err := password.New(
		func(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
			return &authstack.Principal{
				ID:       "pl_xy22ykkds",
				Type:     authstack.PrincipalUser,
				Provider: authstack.ProviderPassword,
			}, nil
		},
		func(ctx context.Context, identifier string) (principal *authstack.Principal, hashedSecret string, err error) {
			hs, _ := cfg.Hasher.Hash(ctx, "weak password")
			return &authstack.Principal{
				ID:       "pl_xy22ykkds",
				Type:     authstack.PrincipalUser,
				Provider: authstack.ProviderPassword,
			}, hs, nil
		},
		cfg,
	)

	if err != nil {
		t.Fatalf("password.New() error = %v", err)
	}

	_, err = auth.AuthenticatePrincipal(context.Background(), "mark@authstack.dev", "weak password")
	if err != nil {
		t.Fatalf("auth.AuthenticatePrincipal() error = %v", err)
	}
}

func TestPasswordAuth_AuthenticatePrincipalAnd(t *testing.T) {
	cfg := password.NewConfig()
	principal := &authstack.Principal{ID: "pl_xy22ykkds", Type: authstack.PrincipalUser}
	hashedSecret, err := cfg.Hasher.Hash(context.Background(), "weak password")
	if err != nil {
		t.Fatalf("cfg.Hasher.Hash() error = %v", err)
	}

	auth, err := password.New(
		func(context.Context, string, string) (*authstack.Principal, error) {
			return principal, nil
		},
		func(context.Context, string) (*authstack.Principal, string, error) {
			return principal, hashedSecret, nil
		},
		cfg,
	)
	if err != nil {
		t.Fatalf("password.New() error = %v", err)
	}

	tx := &authenticationTransaction{principal: principal, hashedSecret: hashedSecret}
	var callbackPrincipal *authstack.Principal
	got, err := auth.AuthenticatePrincipalAnd(
		context.Background(),
		"mark@authstack.dev",
		"weak password",
		tx,
		func(_ context.Context, p *authstack.Principal) error {
			callbackPrincipal = p
			return nil
		},
	)
	if err != nil {
		t.Fatalf("auth.AuthenticatePrincipalAnd() error = %v", err)
	}
	if got != principal || callbackPrincipal != principal {
		t.Fatal("AuthenticatePrincipalAnd() did not return the authenticated principal")
	}
	if got.Provider != authstack.ProviderPassword {
		t.Fatalf("principal.Provider = %q, want %q", got.Provider, authstack.ProviderPassword)
	}
}

func TestPasswordAuth_RegisterPrincipal(t *testing.T) {
	cfg := password.NewConfig()
	auth, err := password.New(
		func(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
			return &authstack.Principal{
				ID:       "pl_xy22ykkds",
				Type:     authstack.PrincipalUser,
				Provider: authstack.ProviderPassword,
			}, nil
		},
		func(ctx context.Context, identifier string) (principal *authstack.Principal, hashedSecret string, err error) {
			hs, _ := cfg.Hasher.Hash(ctx, "weak password")
			return &authstack.Principal{
				ID:       "pl_xy22ykkds",
				Type:     authstack.PrincipalUser,
				Provider: authstack.ProviderPassword,
			}, hs, nil
		},
		cfg,
	)

	if err != nil {
		t.Fatalf("password.New() error = %v", err)
	}

	_, err = auth.RegisterPrincipal(context.Background(), "mark@authstack.dev", "weak password")
	if err != nil {
		t.Fatalf("auth.RegisterPrincipal() error = %v", err)
	}
}

func TestPasswordAuth_RegisterPrincipalAnd(t *testing.T) {
	cfg := password.NewConfig()
	principal := &authstack.Principal{ID: "pl_xy22ykkds", Type: authstack.PrincipalUser}
	auth, err := password.New(
		func(context.Context, string, string) (*authstack.Principal, error) {
			return principal, nil
		},
		func(context.Context, string) (*authstack.Principal, string, error) {
			return principal, "", nil
		},
		cfg,
	)
	if err != nil {
		t.Fatalf("password.New() error = %v", err)
	}

	tx := &registrationTransaction{principal: principal}
	callbackErr := errors.New("profile creation failed")
	_, err = auth.RegisterPrincipalAnd(
		context.Background(),
		"mark@authstack.dev",
		"weak password",
		tx,
		func(_ context.Context, p *authstack.Principal) error {
			if p != principal {
				t.Fatal("callback received a different principal")
			}
			return callbackErr
		},
	)
	if !errors.Is(err, callbackErr) {
		t.Fatalf("auth.RegisterPrincipalAnd() error = %v, want %v", err, callbackErr)
	}
	if tx.hashedSecret == "" || tx.hashedSecret == "weak password" {
		t.Fatal("RegisterPrincipalAnd() did not pass a password hash to the transaction")
	}
}
