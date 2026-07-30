package sdwit

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/golang-jwt/jwt/v5"
)

// IssueOptions carries parameters for issuing an SD-WIT.
type IssueOptions struct {
	// Subject is the workload's identity URI (spiffe:// or wimse://).
	Subject string
	// TrustDomain is the optional trust-domain string.
	TrustDomain string
	// Audiences are optional JWT audiences (always visible — not selectively disclosable).
	Audiences []string
	// Roles is an optional list of role strings for RBAC/ABAC.
	Roles []string
	// WorkloadKey is embedded in cnf.jwk (always visible).
	WorkloadKey *ecdsa.PublicKey
	// KeyID is an optional identifier placed in cnf.jwk.kid.
	KeyID string
	// Selective controls which claims become selectively disclosable.
	// Claims not selected here are placed directly in the JWT payload (always visible).
	Selective SelectiveClaims
}

// Issuer issues SD-JWT Workload Identity Tokens.
type Issuer struct {
	issuerID string
	key      *ecdsa.PrivateKey
	ttl      time.Duration
}

// NewIssuer creates an SD-WIT Issuer.
func NewIssuer(issuerID string, key *ecdsa.PrivateKey, ttl time.Duration) *Issuer {
	return &Issuer{issuerID: issuerID, key: key, ttl: ttl}
}

// Issue creates and returns a full SD-JWT string:
//
//	<Issuer-signed JWT>~<Disclosure1>~<Disclosure2>~...~
//
// The trailing tilde is always present for consistent parsing.
func (i *Issuer) Issue(opts IssueOptions) (string, error) {
	if opts.Subject == "" {
		return "", errors.New("subject is required")
	}
	if opts.WorkloadKey == nil {
		return "", errors.New("workload public key is required")
	}

	// Serialize cnf.jwk
	jwk, err := keys.PublicKeyToJWK(opts.WorkloadKey, opts.KeyID)
	if err != nil {
		return "", fmt.Errorf("serialize workload key: %w", err)
	}
	jwkRaw, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("marshal JWK: %w", err)
	}

	now := time.Now()
	exp := now.Add(i.ttl)

	// Build JWT payload — always-visible claims first.
	payload := jwt.MapClaims{
		"iss":     i.issuerID,
		"iat":     now.Unix(),
		"nbf":     now.Unix(),
		"exp":     exp.Unix(),
		"jti":     newJTI(),
		"cnf":     map[string]interface{}{"jwk": json.RawMessage(jwkRaw)},
		"_sd_alg": sdAlg,
	}
	if len(opts.Audiences) > 0 {
		payload["aud"] = opts.Audiences
	}

	// Accumulate selective disclosures.
	var disclosures []string
	var sdHashes []string

	makeSD := func(name string, value interface{}) error {
		salt, err := newSalt()
		if err != nil {
			return err
		}
		disc, err := buildDisclosure(salt, name, value)
		if err != nil {
			return err
		}
		disclosures = append(disclosures, disc)
		sdHashes = append(sdHashes, hashDisclosure(disc))
		return nil
	}

	// sub
	if opts.Selective.Sub {
		if err := makeSD("sub", opts.Subject); err != nil {
			return "", err
		}
	} else {
		payload["sub"] = opts.Subject
	}

	// trust_domain
	if opts.TrustDomain != "" {
		if opts.Selective.TrustDomain {
			if err := makeSD("trust_domain", opts.TrustDomain); err != nil {
				return "", err
			}
		} else {
			payload["trust_domain"] = opts.TrustDomain
		}
	}

	// roles
	if len(opts.Roles) > 0 {
		if opts.Selective.Roles {
			if err := makeSD("roles", opts.Roles); err != nil {
				return "", err
			}
		} else {
			payload["roles"] = opts.Roles
		}
	}

	if len(sdHashes) > 0 {
		payload["_sd"] = sdHashes
	}

	// Sign the JWT.
	token := jwt.NewWithClaims(jwt.SigningMethodES256, payload)
	token.Header["typ"] = WITTyp
	signedJWT, err := token.SignedString(i.key)
	if err != nil {
		return "", fmt.Errorf("sign SD-WIT: %w", err)
	}

	// Concatenate: <JWT>~<disc1>~<disc2>~...~
	parts := append([]string{signedJWT}, disclosures...)
	parts = append(parts, "") // trailing tilde
	return strings.Join(parts, "~"), nil
}

// newJTI returns a compact random 16-byte hex identifier.
func newJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return fmt.Sprintf("%x", b)
}
