package exchange

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// NewRouter creates the Gin router for the Token Exchange Service.
func NewRouter(cfg *ExchangeConfig) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.POST("/token/exchange", ExchangeHandler(cfg))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	return r
}
