package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/errors"
	"github.com/rs/zerolog/log"
)

func (api *LauthAPI) PostAuthz(c *gin.Context) {
	ctx, e := NewAuthzContext(api, c)
	if e != nil {
		errors.SendRedirect(c, e)
		return
	}
	defer ctx.Close()

	ctx.Report.Set("username", ctx.Request.User)

	showLoginForm := func(err error, description string) {
		ctx.Report.SetError(ctx.Request.makeRedirectError(err, errors.InvalidRequest, description))
		ctx.ShowLoginPage(http.StatusForbidden, ctx.Request.User, description)
	}

	if ctx.Request.RequestSubject != ctx.Gin.ClientIP() {
		e := ctx.Request.makeNonRedirectError(nil, errors.AccessDenied, "incorrect login session")
		ctx.ErrorRedirect(e)
		return
	}

	if proceed := ctx.TrySSO(true); proceed {
		return
	}

	if ctx.Request.User == "" || ctx.Request.Password == "" {
		ctx.Report.UserError()
		showLoginForm(nil, "missing username or password")
		return
	}

	conn, err := api.Connector.Connect()
	if err != nil {
		log.Error().
			Err(err).
			Msg("failed to connecting LDAP server")

		e := ctx.Request.makeRedirectError(err, errors.ServerError, "failed to connecting LDAP server")
		ctx.ErrorRedirect(e)
		return
	}
	defer conn.Close()

	if err := conn.LoginTest(ctx.Request.User, ctx.Request.Password); err != nil {
		ctx.Report.UserError()
		RandomDelay()
		showLoginForm(err, "invalid username or password")
		return
	}

	if api.Config.Expire.SSO > 0 {
		api.SetSSOToken(c, ctx.Request.User, ctx.Request.ClientID, true)
	}

	ctx.SendTokens(ctx.Request.User, time.Now())
}
