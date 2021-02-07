package metrics

import (
	"github.com/gin-gonic/gin"
)

var (
	Userinfo = NewEndpointMetrics(
		"userinfo",
		[]string{"method", "client_id", "username", "scope"},
		[]string{"client_id"},
	)
)

func init() {
	Userinfo.MustRegister()
}

func StartUserinfo(ctx *gin.Context) *Context {
	c := Userinfo.Start(ctx)
	c.Set("method", ctx.Request.Method)
	return c
}
