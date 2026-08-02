// Package spiffeclientauth implements OAuth 2.0 client authentication using
// SPIFFE Workload Identity Tokens (WIT-SVIDs) as JWT bearer assertions.
//
// Reference: draft-ietf-oauth-spiffe-client-auth-02 §4 (WIT-SVID profile)
//
// A workload that already holds a WIT can use it as a client_assertion to
// authenticate to an OAuth 2.0 Authorization Server's token endpoint — with
// no pre-shared client secrets or separately registered credentials.
//
// Request shape (application/x-www-form-urlencoded):
//
//	grant_type=client_credentials
//	client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//	client_assertion=<compact WIT JWT>
//	scope=<requested scope>
//
// The Authenticator (AS-side) validates the WIT with the configured wit.Validator
// and returns an opaque bearer AccessToken bound to the workload's SPIFFE ID.
package spiffeclientauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/wit"
)

// ClientAssertionType is the OAuth 2.0 JWT bearer assertion type per RFC 7523.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// AuthRequest represents an OAuth client credentials request with a WIT-SVID assertion.
type AuthRequest struct {
	// ClientAssertion is the compact WIT JWT used as the client credential.
	ClientAssertion string
	// ClientAssertionType must be ClientAssertionType.
	ClientAssertionType string
	// Scope is the requested OAuth scope (optional).
	Scope string
}

// AccessToken represents an OAuth 2.0 bearer access token response.
type AccessToken struct {
	// Token is the opaque bearer token string.
	Token string `json:"access_token"`
	// TokenType is always "Bearer".
	TokenType string `json:"token_type"`
	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
	// Scope is the granted scope (may be empty).
	Scope string `json:"scope,omitempty"`
	// Sub is the SPIFFE ID of the authenticated workload.
	Sub string `json:"sub"`
}

// Authenticator is the AS-side component that validates WIT-SVID client assertions
// and issues OAuth access tokens.
//
// It uses a configured wit.Validator to verify the presented WIT, then issues
// a short-lived opaque bearer token associated with the workload's SPIFFE ID.
type Authenticator struct {
	issuerID     string
	witValidator *wit.Validator
	tokenTTL     time.Duration
}

// NewAuthenticator creates an Authenticator.
// issuerID identifies this token endpoint (used in error messages).
// ttl is the lifetime of issued access tokens; zero or negative uses 1 hour.
func NewAuthenticator(issuerID string, witValidator *wit.Validator, ttl time.Duration) *Authenticator {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Authenticator{issuerID: issuerID, witValidator: witValidator, tokenTTL: ttl}
}

// Authenticate validates a WIT-SVID client assertion and issues an OAuth access token.
//
// Checks performed:
//   - client_assertion_type == ClientAssertionType
//   - WIT signature, expiry, issuer (via the configured wit.Validator)
//   - WIT is not empty
//
// Returns an AccessToken whose Sub is the workload's SPIFFE URI (from the WIT sub claim).
func (a *Authenticator) Authenticate(req AuthRequest) (*AccessToken, error) {
	if req.ClientAssertionType != ClientAssertionType {
		return nil, fmt.Errorf("unsupported client_assertion_type %q; want %q",
			req.ClientAssertionType, ClientAssertionType)
	}
	if req.ClientAssertion == "" {
		return nil, errors.New("client_assertion is required")
	}

	result, err := a.witValidator.Validate(req.ClientAssertion)
	if err != nil {
		return nil, fmt.Errorf("invalid client_assertion (WIT validation failed): %w", err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	return &AccessToken{
		Token:     base64.RawURLEncoding.EncodeToString(raw),
		TokenType: "Bearer",
		ExpiresIn: int(a.tokenTTL.Seconds()),
		Scope:     req.Scope,
		Sub:       result.Claims.Subject,
	}, nil
}
