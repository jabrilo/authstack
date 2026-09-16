package scsaccessor

import (
	"context"
	"errors"
	"testing"

	"github.com/alexedwards/scs/v2"
)

func TestNewRequiresSessionManager(t *testing.T) {
	_, err := New(nil)
	if !errors.Is(err, ErrSessionManagerRequired) {
		t.Fatalf("New() error = %v, want %v", err, ErrSessionManagerRequired)
	}
}

func TestAccessorSetAndClear(t *testing.T) {
	manager := scs.New()
	accessor, err := New(manager)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, err := manager.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	accessor.Set(ctx, "session-1")
	if got := manager.GetString(ctx, defaultSessionKey); got != "session-1" {
		t.Fatalf("GetString() = %q, want %q", got, "session-1")
	}

	accessor.Clear(ctx)
	if got := manager.GetString(ctx, defaultSessionKey); got != "" {
		t.Fatalf("GetString() after Clear() = %q, want empty", got)
	}
}

func TestNewWithKey(t *testing.T) {
	manager := scs.New()
	accessor, err := NewWithKey(manager, "custom-session-key")
	if err != nil {
		t.Fatalf("NewWithKey() error = %v", err)
	}

	ctx, err := manager.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	accessor.Set(ctx, "session-1")
	if got := manager.GetString(ctx, "custom-session-key"); got != "session-1" {
		t.Fatalf("GetString() = %q, want %q", got, "session-1")
	}
}
