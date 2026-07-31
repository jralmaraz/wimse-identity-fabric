package idp

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// NewRouter creates and configures the Gin router for the IdP.
func NewRouter(cfg *IdPConfig) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.POST("/wit/issue", IssueHandler(cfg))
	r.GET("/.well-known/jwks.json", JWKSHandler(cfg))
	r.GET("/.well-known/openid-federation", EntityConfigHandler(cfg))
	r.GET("/federation/fetch", FederationFetchHandler(cfg))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	return r
}
