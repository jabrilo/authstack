package authstack

import (
	"context"
	"errors"
	"testing"
)

type mockPasswordAuthenticator struct {
	authenticateFn func(ctx context.Context, identifier, secret string) (*Principal, error)
}

func (m *mockPasswordAuthenticator) AuthenticatePassword(ctx context.Context, identifier, secret string) (*Principal, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, identifier, secret)
	}
	return nil, errors.New("austack: mockPasswordAuthenticator.AuthenticatePassword not implemented")
}

func TestPasswordAuthenticator_AuthenticatePassword(t *testing.T) {
	testIdentifierEmail := "testing@authstack.dev"
	testSecret := "this is no secret at all"
	testPrincipalID := "testID"

	tests := []struct {
		name              string
		identifier        string
		secret            string
		mockAuthenticator PasswordAuthenticator
		wantErr           bool
		wantID            string
	}{
		{
			name:       "authentication fails when identifier and secret are empty",
			identifier: "",
			secret:     "",
			mockAuthenticator: &mockPasswordAuthenticator{
				authenticateFn: func(ctx context.Context, identifier, secret string) (*Principal, error) {
					_ = ctx
					if identifier == "" || secret == "" {
						return nil, errors.New("authstack: invalid credentials")
					}
					return &Principal{
						ID:       testPrincipalID,
						Type:     PrincipalUser,
						Claims:   map[string]any{"testing": true},
						Provider: ProviderPassword,
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
			mockAuthenticator: &mockPasswordAuthenticator{
				authenticateFn: func(ctx context.Context, identifier, secret string) (*Principal, error) {
					_ = ctx
					if identifier == testIdentifierEmail && secret == testSecret {
						return &Principal{
							ID:       testPrincipalID,
							Type:     PrincipalUser,
							Claims:   map[string]any{"testing": true},
							Provider: ProviderPassword,
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
			cfg := PasswordConfig{
				Authenticator: tt.mockAuthenticator,
			}

			principal, err := cfg.Authenticator.AuthenticatePassword(context.Background(), tt.identifier, tt.secret)

			if (err != nil) != tt.wantErr {
				t.Fatalf("AuthenticatePassword error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && principal.ID != tt.wantID {
				t.Errorf("Principal ID = %q, want %q", principal.ID, tt.wantID)
			}
		})
	}
}
