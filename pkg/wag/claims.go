// Package wag implements the Workload Authorization Grant
// (draft-carleton-workload-authz-grant-01): a JWT-bearer OAuth grant that
// lets a platform-identified workload obtain access tokens from an
// authorization server without per-workload pre-registration.
//
// The WIT issuer is the natural WAG platform: the same signing key, the same
// issuer identifier, and the same SPIFFE subject — a WIT carries all the
// claims required by the draft. The typ header "wag+jwt" disambiguates the
// grant from the WIT itself ("wit+jwt"), resolving the open JWT-type
// confusion issue noted in the draft.
package wag

import "github.com/golang-jwt/jwt/v5"

// Claims holds the JWT claims for a Workload Authorization Grant.
// The typ header MUST be "wag+jwt".
type Claims struct {
	jwt.RegisteredClaims
	// Scope is the optional space-separated list of requested OAuth scopes.
	Scope string `json:"scope,omitempty"`
}

// AccessTokenClaims are the claims in the access token issued by the AS.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	// Sub identifies the workload that received the token.
	// ClientID is intentionally absent — per-workload client registrations
	// are forbidden by the draft.
	Scope string `json:"scope,omitempty"`
}
