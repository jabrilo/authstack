package authstack

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

type config struct {
	sessionManager SessionManager
	password       PasswordConfig
	oidc           OIDCConfig
	staticToken    StaticTokenConfig
	stateGenFn     func() (string, error)
}

type AuthStack struct {
	cfg config
}

type Option func(*config) error

func New(opts ...Option) (*AuthStack, error) {
	var cfg config

	cfg.stateGenFn = defaultStateGenerator

	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, fmt.Errorf("authstack: option failed: %w", err)
		}
	}

	return &AuthStack{cfg: cfg}, nil
}

func WithSessionManager(sm SessionManager) Option {
	return func(c *config) error {
		c.sessionManager = sm
		return nil
	}
}

func WithProviderPassword(cfg PasswordConfig) Option {
	return func(c *config) error {
		c.password = cfg
		return nil
	}
}

func WithProviderOIDC(cfg OIDCConfig) Option {
	return func(c *config) error {
		c.oidc = cfg
		return nil
	}
}

func WithProviderStaticToken(cfg StaticTokenConfig) Option {
	return func(c *config) error {
		c.staticToken = cfg
		return nil
	}
}

func WithStateGenerator(fn func() (string, error)) Option {
	return func(c *config) error {
		if fn == nil {
			return errors.New("authstack: state generator function cannot be nil")
		}
		c.stateGenFn = fn
		return nil
	}
}

func defaultStateGenerator() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("authstack: failed to generate secure state: %w", err)
	}
	return hex.EncodeToString(b), nil
}
