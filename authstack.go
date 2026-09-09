package authstack

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

type AuthStack struct {
	sessions SessionManager
}

func New(sm SessionManager) (*AuthStack, error) {
	if sm == nil {
		return nil, errors.New("authstack: session manager is required")
	}
	return &AuthStack{sessions: sm}, nil
}

func defaultStateGenerator() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("authstack: failed to generate secure state: %w", err)
	}
	return hex.EncodeToString(b), nil
}
