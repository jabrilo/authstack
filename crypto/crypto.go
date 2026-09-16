package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrStateGenerationFailed = errors.New("authstack: failed to generate secure state")

func GenerateID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("%w: %v", ErrStateGenerationFailed, err)
	}
	return hex.EncodeToString(b), nil
}
