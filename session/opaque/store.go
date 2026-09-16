package opaque

import "context"

type SessionStore interface {
	Create(ctx context.Context, session *Session) error
	Get(ctx context.Context, sessionID string) (*Session, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeAll(ctx context.Context, principalID string) error
}
