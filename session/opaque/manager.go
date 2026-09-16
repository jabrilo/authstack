package opaque

import (
	"context"
	"errors"
	"fmt"
	"time"

	authcrypto "github.com/jabrilo/authstack/crypto"
)

type SessionManager interface {
	Create(ctx context.Context, principalID string, accessor SessionAccessor) (*Session, error)
	Get(ctx context.Context, sessionID string) (*Session, error)
	Revoke(ctx context.Context, sessionID string, accessor SessionAccessor) error
	RevokeAll(ctx context.Context, principalID string) error
}

var (
	ErrSessionStoreRequired    = errors.New("opaque: session store is required")
	ErrSessionAccessorRequired = errors.New("opaque: session accessor is required")
	ErrSessionNotFound         = errors.New("opaque: session not found")
	ErrSessionExpired          = errors.New("opaque: session expired")
	ErrSessionRevoked          = errors.New("opaque: session revoked")
	ErrInvalidSessionTTL       = errors.New("opaque: session TTL must be positive")
)

type Config struct {
	TTL         time.Duration
	IDGenerator func() (string, error)
	Now         func() time.Time
}

type Option func(*Config)

func WithTTL(ttl time.Duration) Option {
	return func(cfg *Config) { cfg.TTL = ttl }
}

func WithIDGenerator(generator func() (string, error)) Option {
	return func(cfg *Config) { cfg.IDGenerator = generator }
}

func WithClock(now func() time.Time) Option {
	return func(cfg *Config) { cfg.Now = now }
}

func NewManager(store SessionStore, opts ...Option) (*Manager, error) {
	if store == nil {
		return nil, ErrSessionStoreRequired
	}

	cfg := Config{
		TTL:         24 * time.Hour,
		IDGenerator: authcrypto.GenerateID,
		Now:         time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.TTL <= 0 {
		return nil, ErrInvalidSessionTTL
	}
	if cfg.IDGenerator == nil {
		cfg.IDGenerator = authcrypto.GenerateID
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &Manager{
		store:       store,
		ttl:         cfg.TTL,
		idGenerator: cfg.IDGenerator,
		now:         cfg.Now,
	}, nil
}

type Manager struct {
	store       SessionStore
	ttl         time.Duration
	idGenerator func() (string, error)
	now         func() time.Time
}

func (m *Manager) Create(ctx context.Context, principalID string, accessor SessionAccessor) (*Session, error) {
	if accessor == nil {
		return nil, ErrSessionAccessorRequired
	}

	id, err := m.idGenerator()
	if err != nil {
		return nil, fmt.Errorf("opaque: generate session ID: %w", err)
	}

	now := m.now()
	session := &Session{
		ID:          id,
		PrincipalID: principalID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(m.ttl),
	}

	if err := m.store.Create(ctx, session); err != nil {
		return nil, err
	}

	if err := accessor.Set(ctx, session.ID); err != nil {
		if revokeErr := m.store.Revoke(ctx, session.ID); revokeErr != nil {
			return nil, fmt.Errorf("opaque: set session accessor: %w (revoke session: %v)", err, revokeErr)
		}
		return nil, fmt.Errorf("opaque: set session accessor: %w", err)
	}

	return session, nil
}

func (m *Manager) Get(ctx context.Context, sessionID string) (*Session, error) {
	session, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}
	if session.RevokedAt != nil {
		return nil, ErrSessionRevoked
	}
	if !session.ExpiresAt.After(m.now()) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

func (m *Manager) Revoke(ctx context.Context, sessionID string, accessor SessionAccessor) error {
	if accessor == nil {
		return ErrSessionAccessorRequired
	}

	if err := m.store.Revoke(ctx, sessionID); err != nil {
		return err
	}
	if err := accessor.Clear(ctx); err != nil {
		return fmt.Errorf("opaque: clear session accessor: %w", err)
	}

	return nil
}

func (m *Manager) RevokeAll(ctx context.Context, principalID string) error {
	return m.store.RevokeAll(ctx, principalID)
}

var _ SessionManager = (*Manager)(nil)
