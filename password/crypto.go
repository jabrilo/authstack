package password

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var ErrMismatchedSecret = errors.New("password: hashed secret does not match provided secret")

type Hasher interface {
	Hash(ctx context.Context, secret string) (string, error)
	Compare(ctx context.Context, hashedSecret, secret string) error
}

type BcryptHasher struct {
	Cost int
}

func DefaultHasher() BcryptHasher {
	return BcryptHasher{Cost: bcrypt.DefaultCost}
}

func (h BcryptHasher) Hash(ctx context.Context, secret string) (string, error) {
	cost := h.Cost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
	if err != nil {
		return "", fmt.Errorf("failed to generate bcrypt hash: %w", err)
	}

	return string(bytes), nil
}

func (h BcryptHasher) Compare(ctx context.Context, hashedSecret, secret string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(secret))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrMismatchedSecret
		}
		return fmt.Errorf("failed to compare hash: %w", err)
	}
	return nil
}
