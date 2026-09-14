package authstack

import (
	"context"
	"time"
)

type Session struct {
	ID          string
	PrincipalID string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

type SessionManager interface {
	Create(ctx context.Context, printipalID string) (*Session, error)
	Get(ctx context.Context, sessionID string) (*Session, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeAll(ctx context.Context, principalID string) error
}

type SessionStore interface {
	Create(ctx context.Context, session *Session) error
	Get(ctx context.Context, sessionID string) (*Session, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeAll(ctx context.Context, principalID string) error
}

type SessionAccessor interface {
	CreateS(ctx context.Context, session *Session) error
	Revoke(ctx context.Context, sessionID string) error
}
