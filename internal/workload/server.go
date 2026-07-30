package workload

import (
	"net/http"

	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/example/wimse-identity-fabric/pkg/wpt"
	"github.com/gin-gonic/gin"
)

// NewProtectedRouter creates a Gin router with WIMSE authentication middleware.
func NewProtectedRouter(witValidator *wit.Validator, wptValidator *wpt.Validator) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(WIMSEAuth(witValidator, wptValidator))
	return r
}

// CallerSubject extracts the caller's subject from the validated WIT in the Gin context.
func CallerSubject(c *gin.Context) string {
	v, exists := c.Get(CtxWITClaims)
	if !exists {
		return ""
	}
	claims, ok := v.(*wit.Claims)
	if !ok {
		return ""
	}
	return claims.Subject
}

// EchoHandler returns a simple handler that echoes the caller's identity.
func EchoHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"caller": CallerSubject(c),
			"echo":   "ok",
		})
	}
}
