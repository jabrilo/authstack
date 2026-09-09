package authstack

import (
	"context"
	"errors"
)

type SessionIssuer interface {
	IssuerSession(ctx context.Context, principal *Principal) error
}

type AuthStack struct {
	sessions SessionManager
}

func New(sm SessionManager) (*AuthStack, error) {
	if sm == nil {
		return nil, errors.New("authstack: session manager is required")
	}
	return &AuthStack{sessions: sm}, nil
}

func (as *AuthStack) IssueSession(ctx context.Context, principal *Principal) error {
	return as.sessions.CreateSession(ctx, principal)
}
