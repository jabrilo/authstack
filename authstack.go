package authstack

import (
	"context"
	"errors"
)

var ErrNilSessionAccessor = errors.New("authstack: session accessor is required")

type SessionIssuer interface {
	IssueSession(ctx context.Context, principal *Principal) error
}

type AuthStack struct {
	sessions SessionAccessor
}

func New(sm SessionAccessor) (*AuthStack, error) {
	if sm == nil {
		return nil, ErrNilSessionAccessor
	}
	return &AuthStack{sessions: sm}, nil
}

func (as *AuthStack) IssueSession(ctx context.Context, principal *Principal) error {
	return as.sessions.CreateSession(ctx, principal)
}
