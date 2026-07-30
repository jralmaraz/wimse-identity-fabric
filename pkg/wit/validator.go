package wit

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/golang-jwt/jwt/v5"
)

// ValidationResult holds the validated claims and the workload's public key.
type ValidationResult struct {
	Claims      *Claims
	WorkloadKey *ecdsa.PublicKey
}

// Validator validates WITs issued by a known IdP.
type Validator struct {
	issuerID string
	idpPub   *ecdsa.PublicKey
	parser   *jwt.Parser
}

// NewValidator creates a Validator for tokens from issuerID signed by idpPub.
func NewValidator(issuerID string, idpPub *ecdsa.PublicKey, opts ...jwt.ParserOption) *Validator {
	base := []jwt.ParserOption{
		jwt.WithIssuer(issuerID),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"ES256"}),
	}
	base = append(base, opts...)
	return &Validator{
		issuerID: issuerID,
		idpPub:   idpPub,
		parser:   jwt.NewParser(base...),
	}
}

// Validate parses and validates the WIT. It returns the claims and the workload's public key.
func (v *Validator) Validate(token string) (*ValidationResult, error) {
	claims := &Claims{}
	t, err := v.parser.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		// Verify typ header
		typ, _ := t.Header["typ"].(string)
		if typ != "wit+jwt" {
			return nil, fmt.Errorf("unexpected typ: %q", typ)
		}
		return v.idpPub, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate WIT: %w", err)
	}
	if !t.Valid {
		return nil, errors.New("WIT is not valid")
	}

	// Extract workload public key from cnf.jwk
	if len(claims.Cnf.JWK) == 0 {
		return nil, errors.New("WIT missing cnf.jwk claim")
	}
	jwk, err := keys.JWKFromRawMessage(claims.Cnf.JWK)
	if err != nil {
		return nil, fmt.Errorf("parse cnf.jwk: %w", err)
	}
	workloadKey, err := keys.JWKToPublicKey(jwk)
	if err != nil {
		return nil, fmt.Errorf("decode workload key: %w", err)
	}

	return &ValidationResult{Claims: claims, WorkloadKey: workloadKey}, nil
}
