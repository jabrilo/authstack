package opaque

import "context"

type SessionAccessor interface {
	CreateS(ctx context.Context, session *Session) error
	Revoke(ctx context.Context, sessionID string) error
}
