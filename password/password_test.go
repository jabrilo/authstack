package password_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jabrilo/authstack"
	"github.com/jabrilo/authstack/password"
)

type mockVerifier struct {
	authenticateFn func(ctx context.Context, identifier, secret string) (*authstack.Principal, error)
}

func (m *mockVerifier) Authenticate(ctx context.Context, identifier, secret string) (*authstack.Principal, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, identifier, secret)
	}
	return nil, errors.New("austack: mockVerifier.AuthenticatePassword not implemented")
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
			//to be implemented
		})
	}
}
