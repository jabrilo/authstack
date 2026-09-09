package authstack

import (
	"errors"
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
