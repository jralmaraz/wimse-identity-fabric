package wit

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/golang-jwt/jwt/v5"
)

// IssueOptions carries parameters for issuing a WIT.
type IssueOptions struct {
	Subject     string
	TrustDomain string
	KeyID       string
	Audiences   []string
	WorkloadKey *ecdsa.PublicKey
}

// Issuer issues WITs signed with its private key.
type Issuer struct {
	issuerID string
	key      *ecdsa.PrivateKey
	ttl      time.Duration
}

// NewIssuer creates a new WIT issuer.
func NewIssuer(issuerID string, key *ecdsa.PrivateKey, ttl time.Duration) *Issuer {
	return &Issuer{issuerID: issuerID, key: key, ttl: ttl}
}

// Issue creates and signs a WIT for the given options.
func (i *Issuer) Issue(opts IssueOptions) (string, error) {
	if opts.Subject == "" {
		return "", errors.New("subject is required")
	}
	if opts.WorkloadKey == nil {
		return "", errors.New("workload public key is required")
	}

	jti, err := generateJTI()
	if err != nil {
		return "", err
	}

	jwk, err := keys.PublicKeyToJWK(opts.WorkloadKey, opts.KeyID)
	if err != nil {
		return "", fmt.Errorf("serialize workload key: %w", err)
	}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("marshal JWK: %w", err)
	}

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuerID,
			Subject:   opts.Subject,
			Audience:  jwt.ClaimStrings(opts.Audiences),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
			ID:        jti,
		},
		TrustDomain: opts.TrustDomain,
		Cnf:         ConfirmationKey{JWK: json.RawMessage(jwkJSON)},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "wit+jwt"

	return token.SignedString(i.key)
}
