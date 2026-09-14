package password_test

import (
	"context"
	"testing"

	"github.com/jabrilo/authstack"
	"github.com/jabrilo/authstack/password"
)

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
