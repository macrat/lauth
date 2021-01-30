package api

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/config"
	"github.com/macrat/ldapin/metrics"
)

type PostAuthzRequest struct {
	GetAuthzRequest

	User     string `form:"username" json:"username" xml:"username"`
	Password string `form:"password" json:"password" xml:"password"`
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

func (req *PostAuthzRequest) BindAndValidate(c *gin.Context, config *config.LdapinConfig) *ErrorMessage {
	if err := req.Bind(c); err != nil {
		return err
	}
	return req.Validate(config)
}

func (api *LdapinAPI) PostAuthz(c *gin.Context) {
	report := metrics.StartPostAuthz()
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

	if req.User == "" || req.Password == "" {
		req.makeRedirectError(nil, InvalidRequest, "missing username or password").Report(report)
		c.HTML(http.StatusForbidden, "login.tmpl", gin.H{
			"endpoints":        api.Config.EndpointPaths(),
			"config":           api.Config,
			"request":          req.GetAuthzRequest,
			"initial_username": req.User,
			"error":            "missing_username_or_password",
		})
		return
	}

	conn, err := api.Connector.Connect()
	if err != nil {
		log.Print(err)
		e := req.makeRedirectError(err, ServerError, "failed to connecting LDAP server")
		e.Report(report)
		e.Redirect(c)
		return
	}
	defer conn.Close()

	if err := conn.LoginTest(req.User, req.Password); err != nil {
		time.Sleep(1 * time.Second)
		req.makeRedirectError(err, InvalidRequest, "invalid username or password").Report(report)
		c.HTML(http.StatusForbidden, "login.tmpl", gin.H{
			"endpoints":        api.Config.EndpointPaths(),
			"config":           api.Config,
			"request":          req.GetAuthzRequest,
			"initial_username": req.User,
			"error":            "invalid_username_or_password",
		})
		return
	}

	if *api.Config.TTL.SSO > 0 {
		ssoToken, err := api.TokenManager.CreateSSOToken(
			api.Config.Issuer,
			req.User,
			time.Now(),
			time.Duration(*api.Config.TTL.SSO),
		)
		if err == nil {
			secure := api.Config.Issuer.Scheme == "https"
			c.SetCookie(
				"token",
				ssoToken,
				int(api.Config.TTL.SSO.IntSeconds()),
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
	}

	c.Redirect(http.StatusFound, resp.String())
}
