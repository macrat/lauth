package metrics

import (
	"github.com/gin-gonic/gin"
)

var (
	Userinfo = NewEndpointMetrics("userinfo", []string{"scope"})
)

func init() {
	Userinfo.MustRegister()
}

func StartUserinfo(c *gin.Context) *Context {
	return Userinfo.Start(c)
}
