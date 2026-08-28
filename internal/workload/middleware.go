package workload

import (
	"net/http"
	"strings"

	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/example/wimse-identity-fabric/pkg/wpt"
	"github.com/gin-gonic/gin"
)

const (
	HeaderWIT = "Workload-Identity-Token"

	// CtxWITClaims is the gin context key for validated WIT claims.
	CtxWITClaims = "wimse_wit_claims"

	// wptScheme is the Authorization header scheme for WPT (draft-ietf-wimse-wpt-02).
	wptScheme = "WPT "
)

// WIMSEAuth returns a Gin middleware that validates WIT+WPT on every request.
// It:
//  1. Extracts WIT from Workload-Identity-Token header
//  2. Validates WIT (issuer, exp, sig) using witValidator
//  3. Extracts WorkloadKey from cnf claim
//  4. Extracts WPT from Authorization: WPT <token> header (draft-ietf-wimse-wpt-02)
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

		// WPT is conveyed via Authorization: WPT <token> (draft-ietf-wimse-wpt-02).
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, wptScheme) {
			c.Header("WWW-Authenticate", "WPT")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing WPT in Authorization header"})
			return
		}
		wptToken := strings.TrimPrefix(authHeader, wptScheme)

		// Build the request URI for audience validation
		scheme := "https"
		if c.Request.TLS == nil {
			scheme = "http"
		}
		requestURI := scheme + "://" + c.Request.Host + c.Request.RequestURI

		_, err = wptValidator.Validate(wpt.ValidateOptions{
			WPTString:         wptToken,
			WITString:         witToken,
			WorkloadPublicKey: witResult.WorkloadKey,
			RequestURI:        requestURI,
			CheckReplay:       true,
		})
		if err != nil {
			c.Header("WWW-Authenticate", "WPT")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid WPT: " + err.Error()})
			return
		}

		c.Set(CtxWITClaims, witResult.Claims)
		c.Next()
	}
}
