package exchange

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/gin-gonic/gin"
)

// ExchangeConfig holds the token exchange service configuration.
type ExchangeConfig struct {
	Policy       *TrustPolicy
	TargetIssuer *wit.Issuer
	TokenTTL     time.Duration
}

type exchangeRequest struct {
	Token string `json:"token"`
}

type exchangeResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

// ExchangeHandler handles POST /token/exchange.
func ExchangeHandler(cfg *ExchangeConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req exchangeRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.Token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
			return
		}

		// Peek at the issuer claim without validating the signature
		issuer, err := peekIssuer(req.Token)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "malformed token"})
			return
		}

		issuerKey := cfg.Policy.IssuerKey(issuer)
		if issuerKey == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "issuer not trusted"})
			return
		}

		// Fully validate the incoming WIT with the trusted issuer's key
		srcValidator := wit.NewValidator(issuer, issuerKey)
		vr, err := srcValidator.Validate(req.Token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token: " + err.Error()})
			return
		}

		if !cfg.Policy.Allows(issuer, vr.Claims.Subject) {
			c.JSON(http.StatusForbidden, gin.H{"error": "subject not allowed"})
			return
		}

		// Apply optional subject rewrite
		newSubject := cfg.Policy.MapSubject(vr.Claims.Subject)

		// Issue a new WIT from the target domain's issuer
		newToken, err := cfg.TargetIssuer.Issue(wit.IssueOptions{
			Subject:     newSubject,
			WorkloadKey: vr.WorkloadKey,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
			return
		}

		ttlSecs := int(cfg.TokenTTL.Seconds())
		if ttlSecs <= 0 {
			ttlSecs = 3600
		}
		c.JSON(http.StatusOK, exchangeResponse{Token: newToken, ExpiresIn: ttlSecs})
	}
}

// peekIssuer decodes the JWT payload without verifying the signature to extract "iss".
func peekIssuer(tokenStr string) (string, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return "", errors.New("not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid JWT payload encoding")
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", errors.New("invalid JWT payload JSON")
	}
	if claims.Issuer == "" {
		return "", errors.New("missing iss claim")
	}
	return claims.Issuer, nil
}
