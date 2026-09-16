package opaque

import "context"

type SessionManager interface {
	Create(ctx context.Context, printipalID string) (*Session, error)
	Get(ctx context.Context, sessionID string) (*Session, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeAll(ctx context.Context, principalID string) error
}
