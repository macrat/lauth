package metrics

import (
	"github.com/gin-gonic/gin"
)

var (
	Token = NewEndpointMetrics("token", []string{"grant_type", "client_id", "scope"})
)

func init() {
	Token.MustRegister()
}

func StartToken(c *gin.Context) *Context {
	return Token.Start(c)
}
