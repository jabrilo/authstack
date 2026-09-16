package opaque

import (
	"time"
)

type Session struct {
	ID          string
	PrincipalID string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}
