package wag

import (
	"crypto/ecdsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultGrantTTL = 5 * time.Minute

// GrantOptions carries parameters for building a WAG.
type GrantOptions struct {
	// Subject is the workload's immutable identifier (SPIFFE ID or similar).
	// Immutable within the platform; never reassigned.
	Subject string
	// Audience is the authorization server's issuer identifier (single value).
	Audience string
	// Scope is the optional space-separated list of requested OAuth scopes.
	Scope string
	// TTL overrides the platform issuer's default grant lifetime.
	TTL time.Duration
}

// PlatformIssuer signs Workload Authorization Grants on behalf of a platform.
// A single platform registration at the AS covers all workloads the platform
// issues grants for — no per-workload registration is required.
type PlatformIssuer struct {
	issuerID string
	key      *ecdsa.PrivateKey
	ttl      time.Duration
}

// NewPlatformIssuer creates a PlatformIssuer. ttl=0 uses the default 5-minute
// grant lifetime recommended by the draft.
func NewPlatformIssuer(issuerID string, key *ecdsa.PrivateKey, ttl time.Duration) *PlatformIssuer {
	if ttl == 0 {
		ttl = defaultGrantTTL
	}
	return &PlatformIssuer{issuerID: issuerID, key: key, ttl: ttl}
}

// IssuerID returns the platform's issuer identifier.
func (p *PlatformIssuer) IssuerID() string { return p.issuerID }

// Issue builds and signs a WAG JWT for the given workload.
// The returned string is the compact JWT representation suitable for use as
// the assertion parameter in an OAuth token request.
func (p *PlatformIssuer) Issue(opts GrantOptions) (string, error) {
	if opts.Subject == "" {
		return "", errors.New("wag: subject is required")
	}
	if opts.Audience == "" {
		return "", errors.New("wag: audience is required")
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = p.ttl
	}

	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuerID,
			Subject:   opts.Subject,
			Audience:  jwt.ClaimStrings{opts.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        jti,
		},
		Scope: opts.Scope,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "wag+jwt"
	return token.SignedString(p.key)
}
