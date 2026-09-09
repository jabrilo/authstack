package authstack

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrStateGenerationFailed = errors.New("authstack: failed to generate secure sate")

func defaultStateGenerator() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("%w: %v", err, err)
	}
	return hex.EncodeToString(b), nil
}
