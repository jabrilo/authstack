package scsaccessor

import (
	"context"
	"errors"

	"github.com/alexedwards/scs/v2"
	"github.com/jabrilo/authstack/session/opaque"
)

const defaultSessionKey = "authstack_session_id"

var ErrSessionManagerRequired = errors.New("scsaccessor: session manager is required")

type Accessor struct {
	manager *scs.SessionManager
	key     string
}

func New(manager *scs.SessionManager) (*Accessor, error) {
	if manager == nil {
		return nil, ErrSessionManagerRequired
	}

	return &Accessor{
		manager: manager,
		key:     defaultSessionKey,
	}, nil
}

func NewWithKey(manager *scs.SessionManager, key string) (*Accessor, error) {
	if manager == nil {
		return nil, ErrSessionManagerRequired
	}
	if key == "" {
		key = defaultSessionKey
	}

	return &Accessor{
		manager: manager,
		key:     key,
	}, nil
}

func (a *Accessor) Set(ctx context.Context, sessionID string) error {
	a.manager.Put(ctx, a.key, sessionID)
	return nil
}

func (a *Accessor) Clear(ctx context.Context) error {
	a.manager.Remove(ctx, a.key)
	return nil
}

var _ opaque.SessionAccessor = (*Accessor)(nil)
