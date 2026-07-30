package wpt

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultTTL = 5 * time.Minute

// GenerateOptions holds parameters for generating a WPT.
type GenerateOptions struct {
	TargetURI       string
	WIT             string
	WorkloadKey     *ecdsa.PrivateKey
	TTL             time.Duration
	AccessTokenHash string // optional ath
}

// Generate creates and signs a WPT bound to a specific WIT and target URI.
func Generate(opts GenerateOptions) (string, error) {
	if opts.TargetURI == "" {
		return "", errors.New("target URI is required")
	}
	if opts.WIT == "" {
		return "", errors.New("WIT is required")
	}
	if opts.WorkloadKey == nil {
		return "", errors.New("workload key is required")
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}

	jti, err := generateJTI()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{opts.TargetURI},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        jti,
		},
		Wth: hashToken(opts.WIT),
		Ath: opts.AccessTokenHash,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "application/wpt+jwt"

	signed, err := token.SignedString(opts.WorkloadKey)
	if err != nil {
		return "", fmt.Errorf("sign WPT: %w", err)
	}
	return signed, nil
}
