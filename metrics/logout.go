package metrics

import (
	"github.com/gin-gonic/gin"
)

var (
	Logout = NewEndpointMetrics(
		"logout",
		[]string{"client_id", "username", "redirect_uri"},
		[]string{"client_id"},
	)
)

func init() {
	Logout.MustRegister()
}

func StartLogout(c *gin.Context) *Context {
	return Logout.Start(c)
}
