package metrics

import (
	"github.com/gin-gonic/gin"
)

var (
	Userinfo = NewEndpointMetrics(
		"userinfo",
		[]string{"client_id", "username", "scope"},
		[]string{"client_id"},
	)
)

func init() {
	Userinfo.MustRegister()
}

func StartUserinfo(c *gin.Context) *Context {
	return Userinfo.Start(c)
}
