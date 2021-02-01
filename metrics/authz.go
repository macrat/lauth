package metrics

import (
	"github.com/gin-gonic/gin"
)

var (
	Authz = NewEndpointMetrics("authz", []string{"method", "response_type", "client_id", "scope", "prompt", "authn_by"})
)

func init() {
	Authz.MustRegister()
}

func StartAuthz(ctx *gin.Context) *Context {
	c := Authz.Start(ctx)
	c.Set("method", ctx.Request.Method)
	return c
}
