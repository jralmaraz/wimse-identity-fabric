package wpt

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ValidateOptions holds parameters for validating a WPT.
type ValidateOptions struct {
	WPTString         string
	WITString         string
	WorkloadPublicKey *ecdsa.PublicKey
	RequestURI        string
	CheckReplay       bool
}

// Validator validates WPTs and optionally tracks JTIs for replay protection.
//
// The replay store maps each JTI to the token's expiry time. On every replay
// check, entries whose expiry has passed are swept out first. This bounds
// memory to the set of JTIs that are still within their validity window —
// typically a few minutes' worth at the configured WPT TTL.
//
// Safety: a replayed-but-expired token is always rejected by the expiry check
// before reaching the replay check, so evicting a JTI once its exp has passed
// cannot open a replay window.
type Validator struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti → expiry
}

// NewValidator creates a new WPT validator.
func NewValidator() *Validator {
	return &Validator{seen: make(map[string]time.Time)}
}

// Validate checks the WPT signature, expiry, audience, wth binding, and optionally jti replay.
func (v *Validator) Validate(opts ValidateOptions) (*Claims, error) {
	if opts.WPTString == "" {
		return nil, errors.New("WPT string is required")
	}
	if opts.WITString == "" {
		return nil, errors.New("WIT string is required")
	}
	if opts.WorkloadPublicKey == nil {
		return nil, errors.New("workload public key is required")
	}
	if opts.RequestURI == "" {
		return nil, errors.New("request URI is required")
	}

	parser := jwt.NewParser(
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithAudience(opts.RequestURI),
	)

	claims := &Claims{}
	t, err := parser.ParseWithClaims(opts.WPTString, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		typ, _ := t.Header["typ"].(string)
		if typ != "application/wpt+jwt" {
			return nil, fmt.Errorf("unexpected typ: %q", typ)
		}
		return opts.WorkloadPublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate WPT: %w", err)
	}
	if !t.Valid {
		return nil, errors.New("WPT is not valid")
	}

	// Verify wth binds this WPT to the presented WIT.
	expectedWth := hashToken(opts.WITString)
	if claims.Wth != expectedWth {
		return nil, errors.New("WPT wth does not match WIT hash")
	}

	// Replay protection: record the JTI and reject any second use.
	if opts.CheckReplay {
		jti := claims.ID
		if jti == "" {
			return nil, errors.New("WPT missing jti for replay check")
		}
		exp := claims.ExpiresAt.Time
		now := time.Now()

		v.mu.Lock()
		// Sweep out entries that have already expired. Expired tokens are
		// rejected by the parser before reaching this point, so removing
		// them cannot create a replay window.
		for id, expiry := range v.seen {
			if now.After(expiry) {
				delete(v.seen, id)
			}
		}
		_, replayed := v.seen[jti]
		if !replayed {
			v.seen[jti] = exp
		}
		v.mu.Unlock()

		if replayed {
			return nil, errors.New("WPT jti already seen (replay attack)")
		}
	}

	return claims, nil
}
