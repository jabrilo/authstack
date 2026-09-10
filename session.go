package authstack

import "context"

type SessionAccessor interface {
	CreateSession(ctx context.Context, p *Principal) error
	GetSession(ctx context.Context) (*Principal, error)
	RevokeSession(ctx context.Context, principalID string) error
}
