package authstack

import (
	"context"
	"errors"
)

var ErrNilSessionManager = errors.New("authstack: session manager is required")

type SessionIssuer interface {
	IssuerSession(ctx context.Context, principal *Principal) error
}

type AuthStack struct {
	sessions SessionManager
}

func New(sm SessionManager) (*AuthStack, error) {
	if sm == nil {
		return nil, ErrNilSessionManager
	}
	return &AuthStack{sessions: sm}, nil
}

func (as *AuthStack) IssueSession(ctx context.Context, principal *Principal) error {
	return as.sessions.CreateSession(ctx, principal)
}
