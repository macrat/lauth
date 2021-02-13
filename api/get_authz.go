package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (api *LauthAPI) GetAuthz(c *gin.Context) {
	ctx, errMsg := NewAuthzContext(api, c)
	if errMsg != nil {
		errMsg.Redirect(c)
		return
	}
	defer ctx.Close()

	if errMsg := ctx.Request.Validate(api.Config); errMsg != nil {
		ctx.ErrorRedirect(errMsg)
		return
	}

	if ctx.Request.User != "" || ctx.Request.Password != "" {
		ctx.ErrorRedirect(ctx.Request.makeRedirectError(nil, InvalidRequest, "can't set username or password in GET method"))
		return
	}

	if proceed := ctx.TrySSO(false); proceed {
		return
	}

	ctx.ShowLoginPage(http.StatusOK, ctx.Request.LoginHint, "")
}
