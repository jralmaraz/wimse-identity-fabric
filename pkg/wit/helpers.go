package wit

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// generateJTI returns a cryptographically random 128-bit base64url string.
func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
