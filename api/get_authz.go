package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/errors"
)

func (api *LauthAPI) GetAuthz(c *gin.Context) {
	ctx, err := NewAuthzContext(api, c)
	if err != nil {
		errors.SendRedirect(c, err)
		return
	}
	defer ctx.Close()

	if ctx.Request.User != "" || ctx.Request.Password != "" {
		ctx.ErrorRedirect(ctx.Request.makeRedirectError(nil, errors.InvalidRequest, "can't set username or password in GET method"))
		return
	}

	if proceed := ctx.TrySSO(false); proceed {
		return
	}

	ctx.ShowLoginPage(http.StatusOK, ctx.Request.LoginHint, "")
}
