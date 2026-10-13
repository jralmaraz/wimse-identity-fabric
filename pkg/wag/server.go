package wag

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// PlatformRegistration is the one-time admin record held by the AS for each
// trusted platform. Individual workloads are never registered here; the AS
// accepts any sub value signed by the platform key.
type PlatformRegistration struct {
	// IssuerID is the platform's HTTPS issuer identifier (simple string
	// comparison per RFC 7523 §3 — no normalisation).
	IssuerID string
	// PublicKey is used to verify grant signatures. Held per registration so
	// one platform's key never validates another's grants.
	PublicKey *ecdsa.PublicKey
	// DistinguishingClaim and DistinguishingValue support multi-tenant
	// platforms that share an issuer identifier. When set, every grant MUST
	// carry the claim with exactly this value; grants lacking it are rejected.
	DistinguishingClaim string
	DistinguishingValue string
}

// TokenResponse carries the token endpoint response fields.
type TokenResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Scope       string
}

// AuthorizationServer is an in-memory OAuth AS that accepts WAG grants from
// registered platforms and issues short-lived access tokens. Refresh tokens
// are never issued (draft §5).
type AuthorizationServer struct {
	issuerID       string
	key            *ecdsa.PrivateKey
	accessTokenTTL time.Duration

	mu        sync.Mutex
	platforms []PlatformRegistration
	usedJTIs  map[string]time.Time // jti → expiry, for replay protection
}

// NewAuthorizationServer creates an AS. accessTokenTTL=0 defaults to 15 min.
func NewAuthorizationServer(issuerID string, key *ecdsa.PrivateKey, accessTokenTTL time.Duration) *AuthorizationServer {
	if accessTokenTTL == 0 {
		accessTokenTTL = 15 * time.Minute
	}
	return &AuthorizationServer{
		issuerID:       issuerID,
		key:            key,
		accessTokenTTL: accessTokenTTL,
		usedJTIs:       make(map[string]time.Time),
	}
}

// RegisterPlatform adds a trusted platform. Safe to call concurrently.
func (s *AuthorizationServer) RegisterPlatform(reg PlatformRegistration) error {
	if reg.IssuerID == "" {
		return errors.New("wag: platform issuer ID is required")
	}
	if reg.PublicKey == nil {
		return errors.New("wag: platform public key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.platforms = append(s.platforms, reg)
	return nil
}

// Exchange validates a WAG and issues an access token.
// requestedScope overrides any scope in the grant; pass "" to use the grant's scope.
func (s *AuthorizationServer) Exchange(grantJWT string, requestedScope string) (*TokenResponse, error) {
	// Parse unverified to extract iss and any distinguishing claims for lookup.
	raw, _, err := jwt.NewParser().ParseUnverified(grantJWT, jwt.MapClaims{})
	if err != nil {
		return nil, errors.New("wag: malformed grant JWT")
	}
	rawClaims, _ := raw.Claims.(jwt.MapClaims)

	iss, _ := rawClaims["iss"].(string)
	if iss == "" {
		return nil, errors.New("wag: missing iss claim")
	}

	reg, err := s.matchPlatform(iss, rawClaims)
	if err != nil {
		return nil, err
	}

	// Verify signature under the matched platform's key only.
	token, err := jwt.ParseWithClaims(grantJWT, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, errors.New("wag: unexpected signing method")
		}
		if t.Header["typ"] != "wag+jwt" {
			return nil, fmt.Errorf("wag: unexpected typ %q, want wag+jwt", t.Header["typ"])
		}
		return reg.PublicKey, nil
	},
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithAudience(s.issuerID),
	)
	if err != nil {
		return nil, fmt.Errorf("wag: invalid grant: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("wag: invalid claims")
	}
	if claims.Subject == "" {
		return nil, errors.New("wag: missing sub claim")
	}
	if claims.ID == "" {
		return nil, errors.New("wag: missing jti claim")
	}

	if err := s.consumeJTI(claims.ID, claims.ExpiresAt.Time); err != nil {
		return nil, err
	}

	scope := requestedScope
	if scope == "" {
		scope = claims.Scope
	}

	accessToken, err := s.mintAccessToken(claims.Subject, scope)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.accessTokenTTL.Seconds()),
		Scope:       scope,
	}, nil
}

// matchPlatform finds a registration whose issuer matches iss and whose
// distinguishing claim (if any) is satisfied by the grant's claims.
func (s *AuthorizationServer) matchPlatform(iss string, claims jwt.MapClaims) (PlatformRegistration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var matched *PlatformRegistration
	for i := range s.platforms {
		reg := &s.platforms[i]
		if reg.IssuerID != iss {
			continue
		}
		if reg.DistinguishingClaim != "" {
			val, _ := claims[reg.DistinguishingClaim].(string)
			if val != reg.DistinguishingValue {
				continue
			}
		}
		if matched != nil {
			return PlatformRegistration{}, errors.New("wag: grant matches multiple platform registrations")
		}
		matched = reg
	}
	if matched == nil {
		return PlatformRegistration{}, errors.New("wag: no matching platform registration (invalid_grant)")
	}
	return *matched, nil
}

// consumeJTI records a jti to prevent replay. Returns an error if already seen.
func (s *AuthorizationServer) consumeJTI(jti string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict expired JTIs to bound memory.
	now := time.Now()
	for id, exp := range s.usedJTIs {
		if now.After(exp) {
			delete(s.usedJTIs, id)
		}
	}

	if _, seen := s.usedJTIs[jti]; seen {
		return errors.New("wag: jti already used (replay detected)")
	}
	s.usedJTIs[jti] = expiry
	return nil
}

// mintAccessToken issues a short-lived signed access token for the workload.
func (s *AuthorizationServer) mintAccessToken(subject, scope string) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuerID,
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			ID:        jti,
		},
		Scope: scope,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "at+jwt"
	return token.SignedString(s.key)
}
