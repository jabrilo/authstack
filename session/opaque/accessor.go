package opaque

import "context"

type SessionAccessor interface {
	Set(ctx context.Context, sessionID string) error
	Clear(ctx context.Context) error
}
