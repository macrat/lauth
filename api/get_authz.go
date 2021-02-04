package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/metrics"
)

type GetAuthzRequest struct {
	ResponseType string `form:"response_type" json:"response_type" xml:"response_type"`
	ClientID     string `form:"client_id"     json:"client_id"     xml:"client_id"`
	RedirectURI  string `form:"redirect_uri"  json:"redirect_uri"  xml:"redirect_uri"`
	Scope        string `form:"scope"         json:"scope"         xml:"scope"`
	State        string `form:"state"         json:"state"         xml:"state"`
	Nonce        string `form:"nonce"         json:"nonce"         xml:"nonce"`
	Prompt       string `form:"prompt"        json:"prompt"        xml:"prompt"`
	MaxAge       int64  `form:"max_age"       json:"max_age"       xml:"max_age"`
	LoginHint    string `form:"login_hint"    json:"login_hint"    xml:"login_hint"`
	Request      string `form:"request"       json:"request"       xml:"request"`
	RequestURI   string `form:"request_uri"   json:"request_uri"   xml:"request_uri"`
}

func (req *GetAuthzRequest) Bind(c *gin.Context) *ErrorMessage {
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

func (req GetAuthzRequest) makeRedirectError(err error, reason ErrorReason, description string) *ErrorMessage {
	redirectURI, e2 := url.Parse(req.RedirectURI)
	if e2 != nil {
		redirectURI = nil
	}

	return &ErrorMessage{
		Err:          err,
		RedirectURI:  redirectURI,
		ResponseType: req.ResponseType,
		State:        req.State,
		Reason:       reason,
		Description:  description,
	}
}

func (req GetAuthzRequest) makeNonRedirectError(err error, reason ErrorReason, description string) *ErrorMessage {
	return &ErrorMessage{
		Err:          err,
		ResponseType: req.ResponseType,
		State:        req.State,
		Reason:       reason,
		Description:  description,
	}
}

func (req GetAuthzRequest) Validate(config *config.Config) *ErrorMessage {
	if req.RedirectURI == "" {
		return req.makeNonRedirectError(nil, InvalidRequest, "redirect_uri is required")
	}

	if u, err := url.Parse(req.RedirectURI); err != nil {
		return req.makeNonRedirectError(err, InvalidRequest, "redirect_uri is invalid format")
	} else if !u.IsAbs() {
		return req.makeNonRedirectError(err, InvalidRequest, "redirect_uri is must be absolute URL")
	}

	if req.ClientID == "" {
		return req.makeNonRedirectError(nil, InvalidClient, "client_id is required")
	}
	if client, ok := config.Clients[req.ClientID]; !ok {
		if !config.DisableClientAuth {
			return req.makeNonRedirectError(
				nil,
				InvalidClient,
				"client_id is not registered",
			)
		}
	} else if !client.RedirectURI.Match(req.RedirectURI) {
		return req.makeNonRedirectError(
			nil,
			UnauthorizedClient,
			"redirect_uri is not registered",
		)
	}

	if req.Request != "" {
		return req.makeRedirectError(
			nil,
			RequestNotSupported,
			"",
		)
	}
	if req.RequestURI != "" {
		return req.makeRedirectError(
			nil,
			RequestURINotSupported,
			"",
		)
	}

	rt := ParseStringSet(req.ResponseType)
	if rt.String() == "" {
		return req.makeRedirectError(
			nil,
			UnsupportedResponseType,
			"response_type is required",
		)
	}
	if err := rt.Validate("response_type", []string{"code", "token", "id_token"}); err != nil {
		return req.makeRedirectError(
			err,
			UnsupportedResponseType,
			err.Error(),
		)
	}
	if !config.AllowImplicitFlow && rt.String() != "code" {
		return req.makeRedirectError(
			nil,
			UnsupportedResponseType,
			"implicit/hybrid flow is disallowed in this server",
		)
	}

	return nil
}

func (req *GetAuthzRequest) Report(c *metrics.Context) {
	c.Set("client_id", req.ClientID)
	c.Set("response_type", req.ResponseType)
	c.Set("scope", req.Scope)
	c.Set("prompt", req.Prompt)
}

func (api *LauthAPI) GetAuthz(c *gin.Context) {
	report := metrics.StartAuthz(c)
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var req GetAuthzRequest
	if err := req.Bind(c); err != nil {
		err.Report(report)
		err.Redirect(c)
		return
	}
	req.Report(report)

	if err := req.Validate(api.Config); err != nil {
		err.Report(report)
		err.Redirect(c)
		return
	}

	prompt := ParseStringSet(req.Prompt)

	report.Set("authn_by", "password")
	if !prompt.Has("login") && !prompt.Has("consent") && !prompt.Has("select_account") && api.Config.Expire.SSO > 0 {
		token, err := api.GetSSOToken(c)
		if err == nil {
			if req.MaxAge <= 0 || req.MaxAge > time.Now().Unix()-token.AuthTime {
				report.Set("authn_by", "sso_token")
				report.Set("username", token.Subject)

				redirect, errMsg := api.makeAuthzTokens(req, token.Subject, time.Unix(token.AuthTime, 0))
				if errMsg != nil {
					errMsg.Report(report)
					errMsg.Redirect(c)
				} else {
					report.Success()
					c.Redirect(http.StatusFound, redirect.String())
				}
				return
			}
		} else if err != http.ErrNoCookie {
			api.DeleteSSOToken(c)
		}
	}

	if ParseStringSet(req.Prompt).Has("none") {
		report.Set("authn_by", "sso_token")
		e := req.makeRedirectError(nil, "login_required", "")
		e.Report(report)
		e.Redirect(c)
		return
	}

	loginToken, err := api.MakeLoginSession(c.ClientIP(), req.ClientID)
	if err != nil {
		e := req.makeRedirectError(err, "server_error", "failed to create session")
		e.Report(report)
		e.Redirect(c)
		return
	}

	report.Continue()
	c.HTML(http.StatusOK, "login.tmpl", gin.H{
		"endpoints":        api.Config.EndpointPaths(),
		"config":           api.Config,
		"request":          req,
		"initial_username": req.LoginHint,
		"session_token":    loginToken,
	})
}
