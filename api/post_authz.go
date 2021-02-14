package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (api *LauthAPI) PostAuthz(c *gin.Context) {
	ctx, errMsg := NewAuthzContext(api, c)
	if errMsg != nil {
		errMsg.Redirect(c)
		return
	}
	defer ctx.Close()

	ctx.Report.Set("username", ctx.Request.User)

	if errMsg := ctx.Request.Validate(api.Config); errMsg != nil {
		ctx.ErrorRedirect(errMsg)
		return
	}

	showLoginForm := func(err error, description string) {
		ctx.Request.makeRedirectError(err, InvalidRequest, description).Report(ctx.Report)
		ctx.ShowLoginPage(http.StatusForbidden, ctx.Request.User, description)
	}

	if err := api.ValidateLoginSession(ctx.Request.SessionToken, ctx.Gin.ClientIP(), ctx.Request.ClientID); err != nil {
		showLoginForm(err, "invalid session")
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

		e := ctx.Request.makeRedirectError(err, ServerError, "failed to connecting LDAP server")
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
		api.SetSSOToken(c, ctx.Request.User)
	}

	ctx.SendTokens(ctx.Request.User, time.Now())
}
