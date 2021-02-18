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

	if err := ctx.Request.Validate(api.Config); err != nil {
		ctx.ErrorRedirect(err)
		return
	}

	if ctx.Request.RequestIssuer() != "" && ctx.Request.RequestIssuer() == api.Config.Issuer.String() {
		ctx.ErrorRedirect(ctx.Request.makeRedirectError(nil, errors.InvalidRequestObject, "invalid request object for GET method"))
		return
	}

	if ctx.Request.User != "" || ctx.Request.Password != "" {
		ctx.ErrorRedirect(ctx.Request.makeRedirectError(nil, errors.InvalidRequest, "can't set username or password in GET method"))
		return
	}

	if proceed := ctx.TrySSO(false); proceed {
		return
	}

	ctx.ShowLoginPage(http.StatusOK, ctx.Request.LoginHint, "")
}
