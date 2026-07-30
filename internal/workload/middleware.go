package workload

import (
	"net/http"

	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/example/wimse-identity-fabric/pkg/wpt"
	"github.com/gin-gonic/gin"
)

const (
	HeaderWIT = "Workload-Identity-Token"
	HeaderWPT = "Workload-Proof-Token"

	// CtxWITClaims is the gin context key for validated WIT claims.
	CtxWITClaims = "wimse_wit_claims"
)

// WIMSEAuth returns a Gin middleware that validates WIT+WPT on every request.
// It:
//  1. Extracts WIT from Workload-Identity-Token header
//  2. Validates WIT (issuer, exp, sig) using witValidator
//  3. Extracts WorkloadKey from cnf claim
//  4. Extracts WPT from Workload-Proof-Token header
//  5. Validates WPT (sig, aud=request URI, wth, exp, jti replay)
//  6. Injects validated WITClaims into Gin context
func WIMSEAuth(witValidator *wit.Validator, wptValidator *wpt.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		witToken := c.GetHeader(HeaderWIT)
		if witToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing " + HeaderWIT})
			return
		}

		witResult, err := witValidator.Validate(witToken)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid WIT: " + err.Error()})
			return
		}

		wptToken := c.GetHeader(HeaderWPT)
		if wptToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing " + HeaderWPT})
			return
		}

		// Build the request URI for audience validation
		scheme := "https"
		if c.Request.TLS == nil {
			scheme = "http"
		}
		requestURI := scheme + "://" + c.Request.Host + c.Request.RequestURI

		_, err = wptValidator.Validate(wpt.ValidateOptions{
			WPTString:        wptToken,
			WITString:        witToken,
			WorkloadPublicKey: witResult.WorkloadKey,
			RequestURI:       requestURI,
			CheckReplay:      true,
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid WPT: " + err.Error()})
			return
		}

		c.Set(CtxWITClaims, witResult.Claims)
		c.Next()
	}
}
