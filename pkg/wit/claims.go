package wit

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the claims carried in a Workload Identity Token (WIT).
// typ header must be "wit+jwt".
type Claims struct {
	jwt.RegisteredClaims
	TrustDomain string          `json:"trust_domain,omitempty"`
	Cnf         ConfirmationKey `json:"cnf"`
}

// ConfirmationKey holds the workload's public key as a JWK raw message.
type ConfirmationKey struct {
	JWK json.RawMessage `json:"jwk"`
}
