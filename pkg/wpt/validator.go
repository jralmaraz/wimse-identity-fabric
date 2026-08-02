package wpt

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// ValidateOptions holds parameters for validating a WPT.
type ValidateOptions struct {
	WPTString         string
	WITString         string
	WorkloadPublicKey *ecdsa.PublicKey
	RequestURI        string
	CheckReplay       bool
	// TxnToken is the optional compact Transaction Token JWT that should be
	// bound to this proof via tth. When set, the validator verifies that
	// claims.Tth == SHA-256(TxnToken). Ignored when empty.
	TxnToken string
}

// Validator validates WPTs and optionally tracks JTIs for replay protection
// via a pluggable JTIStore.
//
// The default store (InMemoryJTIStore) is suitable for single-process
// deployments. Swap it for a distributed store (etcd, Redis, CockroachDB)
// to share replay state across replicas — the plug-in point for
// multi-cloud / multi-replica deployments.
type Validator struct {
	store JTIStore
}

// NewValidator creates a Validator backed by an InMemoryJTIStore.
func NewValidator() *Validator {
	return &Validator{store: NewInMemoryJTIStore()}
}

// NewValidatorWithStore creates a Validator backed by the provided JTIStore.
// Use this to inject a distributed store in multi-replica deployments.
func NewValidatorWithStore(s JTIStore) *Validator {
	return &Validator{store: s}
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
		jwt.WithIssuedAt(),
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

	// Verify tth binds this WPT to the presented Transaction Token (if supplied).
	if opts.TxnToken != "" {
		expectedTth := hashToken(opts.TxnToken)
		if claims.Tth != expectedTth {
			return nil, errors.New("WPT tth does not match Transaction Token hash")
		}
	}

	// Replay protection: delegate to the JTIStore.
	if opts.CheckReplay {
		jti := claims.ID
		if jti == "" {
			return nil, errors.New("WPT missing jti for replay check")
		}
		if err := v.store.Record(jti, claims.ExpiresAt.Time); err != nil {
			return nil, fmt.Errorf("WPT replay check: %w", err)
		}
	}

	return claims, nil
}
