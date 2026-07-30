package sdwit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// newSalt returns a 16-byte cryptographically random salt encoded as base64url.
func newSalt() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// buildDisclosure creates a disclosure string: base64url(json(["salt","name",value])).
// This is the canonical form transmitted after the ~ separator.
func buildDisclosure(salt, name string, value interface{}) (string, error) {
	arr := []interface{}{salt, name, value}
	j, err := json.Marshal(arr)
	if err != nil {
		return "", fmt.Errorf("marshal disclosure: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(j), nil
}

// hashDisclosure returns base64url(sha256(disclosureString)) — the value placed
// in the _sd array of the issuer-signed JWT.
func hashDisclosure(disclosureString string) string {
	h := sha256.Sum256([]byte(disclosureString))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// decodeDisclosure parses a disclosure string and returns [salt, claimName, claimValue].
func decodeDisclosure(disc string) (salt, name string, value interface{}, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(disc)
	if err != nil {
		return "", "", nil, fmt.Errorf("decode disclosure: %w", err)
	}
	var arr []interface{}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return "", "", nil, fmt.Errorf("unmarshal disclosure: %w", err)
	}
	if len(arr) != 3 {
		return "", "", nil, fmt.Errorf("disclosure must have 3 elements, got %d", len(arr))
	}
	saltStr, ok := arr[0].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("disclosure salt must be a string")
	}
	nameStr, ok := arr[1].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("disclosure name must be a string")
	}
	return saltStr, nameStr, arr[2], nil
}
