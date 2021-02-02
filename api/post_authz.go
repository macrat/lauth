package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/metrics"
	"github.com/rs/zerolog/log"
)

type PostAuthzRequest struct {
	GetAuthzRequest

	User       string `form:"username" json:"username" xml:"username"`
	Password   string `form:"password" json:"password" xml:"password"`
	LoginToken string `form:"session"  json:"session"  xml:"session"`
}

func (req *PostAuthzRequest) Bind(c *gin.Context) *ErrorMessage {
	err := c.ShouldBind(req)
	if err != nil {
		return &ErrorMessage{
			Err:         err,
			Reason:      InvalidRequest,
			Description: "failed to parse request",
		}
	}
	return nil
}

func (req *PostAuthzRequest) BindAndValidate(c *gin.Context, config *config.Config) *ErrorMessage {
	if err := req.Bind(c); err != nil {
		return err
	}
	return req.Validate(config)
}

func (api *LauthAPI) PostAuthz(c *gin.Context) {
	report := metrics.StartAuthz(c)
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var req PostAuthzRequest
	if err := (&req).BindAndValidate(c, api.Config); err != nil {
		err.Redirect(c)
		return
	}
	report.Set("authn_by", "password")
	req.Report(report)

	showLoginForm := func(description string) {
		loginToken, err := api.MakeLoginSession(c.ClientIP(), req.ClientID)
		if err != nil {
			e := req.makeRedirectError(err, "server_error", "failed to create session")
			e.Report(report)
			e.Redirect(c)
			return
		}

		req.makeRedirectError(nil, InvalidRequest, description).Report(report)
		c.HTML(http.StatusForbidden, "login.tmpl", gin.H{
			"endpoints":        api.Config.EndpointPaths(),
			"config":           api.Config,
			"request":          req.GetAuthzRequest,
			"initial_username": req.User,
			"error":            description,
			"session_token":    loginToken,
		})
	}

	if req.LoginToken == "" {
		showLoginForm("invalid session")
		return
	} else {
		loginToken, err := api.TokenManager.ParseLoginToken(req.LoginToken)
		if err == nil {
			err = loginToken.Validate(api.Config.Issuer)
		}

		if err != nil || loginToken.Subject != c.ClientIP() || loginToken.ClientID != req.ClientID {
			showLoginForm("invalid session")
			return
		}
	}

	if req.User == "" || req.Password == "" {
		showLoginForm("missing username or password")
		return
	}

	conn, err := api.Connector.Connect()
	if err != nil {
		log.Error().
			Err(err).
			Msg("failed to connecting LDAP server")

		e := req.makeRedirectError(err, ServerError, "failed to connecting LDAP server")
		e.Report(report)
		e.Redirect(c)
		return
	}
	defer conn.Close()

	if err := conn.LoginTest(req.User, req.Password); err != nil {
		RandomDelay()
		showLoginForm("invalid username or password")
		return
	}

	if api.Config.Expire.SSO > 0 {
		ssoToken, err := api.TokenManager.CreateSSOToken(
			api.Config.Issuer,
			req.User,
			time.Now(),
			time.Duration(api.Config.Expire.SSO),
		)
		if err == nil {
			secure := api.Config.Issuer.Scheme == "https"
			c.SetCookie(
				"token",
				ssoToken,
				int(api.Config.Expire.SSO.IntSeconds()),
				"/",
				(*url.URL)(api.Config.Issuer).Hostname(),
				secure,
				true,
			)
		}
	}

	resp, errMsg := api.makeAuthzTokens(req.GetAuthzRequest, req.User, time.Now())
	if errMsg != nil {
		errMsg.Report(report)
		errMsg.Redirect(c)
		return
	}

	log.Debug().
		Str("username", req.User).
		Msg("logged in with username and password")

	c.Redirect(http.StatusFound, resp.String())
}
