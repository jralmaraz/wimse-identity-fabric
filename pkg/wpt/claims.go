package wpt

import "github.com/golang-jwt/jwt/v5"

// Claims represents the claims in a Workload Proof Token (WPT).
// typ header must be "application/wpt+jwt".
type Claims struct {
	jwt.RegisteredClaims
	// Wth is the base64url-encoded SHA-256 hash of the WIT.
	Wth string `json:"wth"`
	// Tth is the optional base64url-encoded SHA-256 hash of a target token.
	Tth string `json:"tth,omitempty"`
}
