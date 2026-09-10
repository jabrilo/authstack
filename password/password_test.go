package password_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jabrilo/authstack"
	"github.com/jabrilo/authstack/password"
)

type mockVerifier struct {
	resolveIdentifierTypeFn func(identifier string) (password.IdentifierType, error)
	authenticateFn          func(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

func (m *mockVerifier) AuthenticatePassword(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, identifier, secret)
	}
	return nil, errors.New("austack: mockVerifier.AuthenticatePassword not implemented")
}

func (m *mockVerifier) ResolveIdendifierType(identifier string) (password.IdentifierType, error) {
	if m.resolveIdentifierTypeFn != nil {
		return m.resolveIdentifierTypeFn(identifier)
	}
	return "", errors.New("authstack: mockVerifier.ResolveIdendifierType not implemented")
}

func TestPasswordAuthenticator_AuthenticatePassword(t *testing.T) {
	testIdentifierEmail := "testing@authstack.dev"
	testSecret := "this is no secret at all"
	testPrincipalID := "testID"

	tests := []struct {
		name         string
		identifier   string
		secret       string
		mockVerifier password.Verifier
		wantErr      bool
		wantID       string
	}{
		{
			name:       "authentication fails when identifier and secret are empty",
			identifier: "",
			secret:     "",
			mockVerifier: &mockVerifier{
				authenticateFn: func(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
					_ = ctx
					if identifier == "" || secret == "" {
						return nil, errors.New("authstack: invalid credentials")
					}
					return &authstack.Principal{
						ID:       testPrincipalID,
						Type:     authstack.PrincipalUser,
						Claims:   map[string]any{"testing": true},
						Provider: authstack.ProviderPassword,
					}, nil
				},
			},
			wantErr: true,
			wantID:  "",
		},
		{
			name:       "authentication succeeds with valid identifiers",
			identifier: testIdentifierEmail,
			secret:     testSecret,
			mockVerifier: &mockVerifier{
				authenticateFn: func(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
					_ = ctx
					if identifier == testIdentifierEmail && secret == testSecret {
						return &authstack.Principal{
							ID:       testPrincipalID,
							Type:     authstack.PrincipalUser,
							Claims:   map[string]any{"testing": true},
							Provider: authstack.ProviderPassword,
						}, nil
					}

					return nil, errors.New("authstack: invalid credentials")
				},
			},
			wantErr: false,
			wantID:  testPrincipalID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := password.Config{
				Verifier: tt.mockVerifier,
			}

			principal, err := cfg.Verifier.AuthenticatePassword(context.Background(), tt.identifier, tt.secret)

			if (err != nil) != tt.wantErr {
				t.Fatalf("AuthenticatePassword error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && principal.ID != tt.wantID {
				t.Errorf("Principal ID = %q, want %q", principal.ID, tt.wantID)
			}
		})
	}
}
