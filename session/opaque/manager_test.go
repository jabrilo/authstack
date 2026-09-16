package opaque

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memoryStore struct {
	sessions map[string]*Session
}

func (s *memoryStore) Create(_ context.Context, session *Session) error {
	if s.sessions == nil {
		s.sessions = make(map[string]*Session)
	}
	s.sessions[session.ID] = session
	return nil
}

func (s *memoryStore) Get(_ context.Context, sessionID string) (*Session, error) {
	return s.sessions[sessionID], nil
}

func (s *memoryStore) Revoke(_ context.Context, sessionID string) error {
	now := time.Now()
	if session := s.sessions[sessionID]; session != nil {
		session.RevokedAt = &now
	}
	return nil
}

func (s *memoryStore) RevokeAll(_ context.Context, principalID string) error {
	now := time.Now()
	for _, session := range s.sessions {
		if session.PrincipalID == principalID {
			session.RevokedAt = &now
		}
	}
	return nil
}

func TestManagerCreateAndGet(t *testing.T) {
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	store := &memoryStore{}
	manager, err := NewManager(
		store,
		WithTTL(time.Hour),
		WithClock(func() time.Time { return now }),
		WithIDGenerator(func() (string, error) { return "session-1", nil }),
	)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	session, err := manager.Create(context.Background(), "principal-1")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if session.ID != "session-1" {
		t.Fatalf("session.ID = %q, want %q", session.ID, "session-1")
	}
	if !session.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("session.ExpiresAt = %v, want %v", session.ExpiresAt, now.Add(time.Hour))
	}

	got, err := manager.Get(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != session {
		t.Fatal("Get() returned a different session")
	}
}

func TestManagerGetRejectsExpiredAndRevokedSessions(t *testing.T) {
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	store := &memoryStore{sessions: map[string]*Session{
		"expired": {
			ID:        "expired",
			ExpiresAt: now,
		},
		"revoked": {
			ID:        "revoked",
			ExpiresAt: now.Add(time.Hour),
			RevokedAt: func() *time.Time { value := now; return &value }(),
		},
	}}
	manager, err := NewManager(store, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	for _, test := range []struct {
		id  string
		err error
	}{
		{id: "expired", err: ErrSessionExpired},
		{id: "revoked", err: ErrSessionRevoked},
		{id: "missing", err: ErrSessionNotFound},
	} {
		_, err := manager.Get(context.Background(), test.id)
		if !errors.Is(err, test.err) {
			t.Errorf("Get(%q) error = %v, want %v", test.id, err, test.err)
		}
	}
}

func TestManagerRevoke(t *testing.T) {
	store := &memoryStore{sessions: map[string]*Session{
		"session-1": {
			ID:        "session-1",
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}}
	manager, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Revoke(context.Background(), "session-1"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if _, err := manager.Get(context.Background(), "session-1"); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Get() error = %v, want %v", err, ErrSessionRevoked)
	}
}
