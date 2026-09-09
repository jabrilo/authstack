package authstack

import "context"

type SessionManager interface {
	CreateSession(ctx context.Context, p Principal) error
	GetSession(ctx context.Context, sessionID string) (*Principal, error)
	RevokeSession(ctx context.Context, sessionID string) error
}
