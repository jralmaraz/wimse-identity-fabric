package identitychaining

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/golang-jwt/jwt/v5"
)

const defaultGrantTTL = 5 * time.Minute

// GrantIssuer is the domain-A AS component that validates a workload's WIT and
// issues a JWT Authorization Grant targeting domain B's token endpoint.
type GrantIssuer struct {
	issuerID     string
	key          *ecdsa.PrivateKey
	witValidator *wit.Validator
	ttl          time.Duration
}

// NewGrantIssuer creates a GrantIssuer.
//
//   - issuerID: domain A's issuer URL (becomes iss in the grant)
//   - key: domain A's signing key (used to sign the grant)
//   - witValidator: validates the incoming WIT before a grant is issued
//   - ttl: grant lifetime; zero or negative uses 5 minutes
func NewGrantIssuer(issuerID string, key *ecdsa.PrivateKey, witValidator *wit.Validator, ttl time.Duration) *GrantIssuer {
	if ttl == 0 {
		ttl = defaultGrantTTL
	}
	return &GrantIssuer{issuerID: issuerID, key: key, witValidator: witValidator, ttl: ttl}
}

// Issue validates subjectToken (a WIT) and issues a JWT Authorization Grant
// addressing targetAudience (domain B's token endpoint URL).
//
// The returned compact JWT carries:
//   - iss: domain A's issuer ID (this AS)
//   - sub: workload SPIFFE ID extracted from the validated WIT
//   - aud: targetAudience (domain B's token endpoint)
//   - iat/exp: issuance and expiry timestamps
//   - jti: unique grant ID (prevents replay)
//   - typ: "jwt-authz-grant"
func (g *GrantIssuer) Issue(subjectToken, targetAudience string) (string, error) {
	if subjectToken == "" {
		return "", errors.New("subject token is required")
	}
	if targetAudience == "" {
		return "", errors.New("target audience is required")
	}

	result, err := g.witValidator.Validate(subjectToken)
	if err != nil {
		return "", fmt.Errorf("validate subject WIT: %w", err)
	}

	jtiRaw := make([]byte, 16)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	now := time.Now()
	claims := GrantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.issuerID,
			Subject:   result.Claims.Subject,
			Audience:  jwt.ClaimStrings{targetAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(g.ttl)),
			ID:        base64.RawURLEncoding.EncodeToString(jtiRaw),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = GrantTokenType
	return t.SignedString(g.key)
}
