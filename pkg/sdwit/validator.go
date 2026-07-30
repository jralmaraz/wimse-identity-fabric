package sdwit

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/golang-jwt/jwt/v5"
)

// Validator validates SD-WIT tokens and unpacks presented disclosures.
type Validator struct {
	issuerID string
	idpKey   *ecdsa.PublicKey
}

// NewValidator creates an SD-WIT Validator.
// issuerID must match the iss claim; idpKey is the IdP's public signing key.
func NewValidator(issuerID string, idpKey *ecdsa.PublicKey) *Validator {
	return &Validator{issuerID: issuerID, idpKey: idpKey}
}

// Validate parses and verifies an SD-JWT string, unpacking all disclosures
// included in the presentation. Claims backed by disclosures not present in
// the token are silently absent from VerifiedClaims (selective disclosure).
//
// The sdJWT string has the form: <signed-JWT>~<disclosure1>~<disclosure2>~...~
func (v *Validator) Validate(sdJWT string) (*VerifiedClaims, error) {
	signedJWT, disclosures, err := splitSDJWT(sdJWT)
	if err != nil {
		return nil, err
	}

	// Parse and verify the issuer-signed JWT.
	parser := jwt.NewParser(
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(v.issuerID),
	)
	mapClaims := jwt.MapClaims{}
	tok, err := parser.ParseWithClaims(signedJWT, mapClaims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		typ, _ := t.Header["typ"].(string)
		if typ != WITTyp {
			return nil, fmt.Errorf("unexpected typ: %q (want %q)", typ, WITTyp)
		}
		return v.idpKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate SD-WIT JWT: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("SD-WIT is not valid")
	}

	// Build a set of the _sd hashes from the JWT payload for O(1) lookup.
	sdHashSet := map[string]bool{}
	if raw, ok := mapClaims["_sd"]; ok {
		hashes, ok := raw.([]interface{})
		if !ok {
			return nil, errors.New("_sd claim is not an array")
		}
		for _, h := range hashes {
			if s, ok := h.(string); ok {
				sdHashSet[s] = true
			}
		}
	}

	// Unpack each provided disclosure, verifying its hash is in _sd.
	disclosed := map[string]interface{}{}
	for _, disc := range disclosures {
		hash := hashDisclosure(disc)
		if !sdHashSet[hash] {
			return nil, fmt.Errorf("disclosure hash not found in _sd (claim may not be selectively disclosable)")
		}
		_, name, value, err := decodeDisclosure(disc)
		if err != nil {
			return nil, err
		}
		if _, exists := disclosed[name]; exists {
			return nil, fmt.Errorf("duplicate disclosure for claim %q", name)
		}
		disclosed[name] = value
	}

	// Extract the workload's public key from cnf.jwk (always required).
	workloadKey, err := extractWorkloadKey(mapClaims)
	if err != nil {
		return nil, err
	}

	// Assemble VerifiedClaims from payload + disclosures.
	result := &VerifiedClaims{WorkloadKey: workloadKey}

	if iss, ok := mapClaims["iss"].(string); ok {
		result.Issuer = iss
	}
	if exp, err := mapClaims.GetExpirationTime(); err == nil && exp != nil {
		result.Expiry = exp.Unix()
	}
	if auds, err := mapClaims.GetAudience(); err == nil {
		result.Audiences = auds
	}

	// sub — from JWT payload (non-selective) or from disclosure
	if sub, ok := mapClaims["sub"].(string); ok {
		result.Subject = sub
	} else if sub, ok := disclosed["sub"].(string); ok {
		result.Subject = sub
	}

	// trust_domain
	if td, ok := mapClaims["trust_domain"].(string); ok {
		result.TrustDomain = td
	} else if td, ok := disclosed["trust_domain"].(string); ok {
		result.TrustDomain = td
	}

	// roles
	result.Roles = extractStringSlice(mapClaims["roles"])
	if result.Roles == nil {
		result.Roles = extractStringSlice(disclosed["roles"])
	}

	return result, nil
}

// splitSDJWT splits "jwt~disc1~disc2~...~" into (jwt, []disclosures).
// The trailing empty element produced by the final tilde is dropped.
func splitSDJWT(sdJWT string) (string, []string, error) {
	parts := strings.Split(sdJWT, "~")
	if len(parts) < 1 || parts[0] == "" {
		return "", nil, errors.New("invalid SD-JWT: empty or missing JWT part")
	}
	signedJWT := parts[0]
	var disclosures []string
	for _, p := range parts[1:] {
		if p != "" {
			disclosures = append(disclosures, p)
		}
	}
	return signedJWT, disclosures, nil
}

// extractWorkloadKey pulls the EC public key out of cnf.jwk in the JWT payload.
func extractWorkloadKey(claims jwt.MapClaims) (*ecdsa.PublicKey, error) {
	cnfRaw, ok := claims["cnf"]
	if !ok {
		return nil, errors.New("missing cnf claim")
	}
	cnfMap, ok := cnfRaw.(map[string]interface{})
	if !ok {
		return nil, errors.New("cnf is not an object")
	}
	jwkRaw, ok := cnfMap["jwk"]
	if !ok {
		return nil, errors.New("cnf.jwk is missing")
	}
	// Re-marshal so we can use keys.JWKFromRawMessage.
	jwkBytes, err := json.Marshal(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("re-marshal cnf.jwk: %w", err)
	}
	jwk, err := keys.JWKFromRawMessage(json.RawMessage(jwkBytes))
	if err != nil {
		return nil, fmt.Errorf("parse cnf.jwk: %w", err)
	}
	return keys.JWKToPublicKey(jwk)
}

// extractStringSlice coerces a []interface{} of strings to []string.
func extractStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
