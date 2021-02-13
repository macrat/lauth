package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/metrics"
)

type AuthzRequest struct {
	ResponseType string `form:"response_type" json:"response_type" xml:"response_type"`
	ClientID     string `form:"client_id"     json:"client_id"     xml:"client_id"`
	RedirectURI  string `form:"redirect_uri"  json:"redirect_uri"  xml:"redirect_uri"`
	Scope        string `form:"scope"         json:"scope"         xml:"scope"`
	State        string `form:"state"         json:"state"         xml:"state"`
	Nonce        string `form:"nonce"         json:"nonce"         xml:"nonce"`
	MaxAge       int64  `form:"max_age"       json:"max_age"       xml:"max_age"`

	// use only GET method
	Prompt    string `form:"prompt"        json:"prompt"        xml:"prompt"`
	LoginHint string `form:"login_hint"    json:"login_hint"    xml:"login_hint"`

	// use only POST method
	User         string `form:"username" json:"username" xml:"username"`
	Password     string `form:"password" json:"password" xml:"password"`
	SessionToken string `form:"session"  json:"session"  xml:"session"`

	// not supported
	Request    string `form:"request"       json:"request"       xml:"request"`
	RequestURI string `form:"request_uri"   json:"request_uri"   xml:"request_uri"`
}

func (req *AuthzRequest) Bind(c *gin.Context) *ErrorMessage {
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

func (req *AuthzRequest) makeRedirectError(err error, reason ErrorReason, description string) *ErrorMessage {
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

func (req *AuthzRequest) makeNonRedirectError(err error, reason ErrorReason, description string) *ErrorMessage {
	return &ErrorMessage{
		Err:          err,
		ResponseType: req.ResponseType,
		State:        req.State,
		Reason:       reason,
		Description:  description,
	}
}

func (req *AuthzRequest) Validate(config *config.Config) *ErrorMessage {
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
		return req.makeNonRedirectError(
			nil,
			InvalidClient,
			"client_id is not registered",
		)
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
	if !config.Clients[req.ClientID].AllowImplicitFlow && rt.String() != "code" {
		return req.makeRedirectError(
			nil,
			UnsupportedResponseType,
			"implicit/hybrid flow is disallowed",
		)
	}

	prompt := ParseStringSet(req.Prompt)
	if prompt.Has("none") && (prompt.Has("login") || prompt.Has("select_account") || prompt.Has("consent")) {
		return req.makeRedirectError(
			nil,
			InvalidRequest,
			"prompt=none can't use same time with login, select_account, or consent",
		)
	}

	if rt.Has("id_token") && req.Nonce == "" {
		return req.makeRedirectError(
			nil,
			InvalidRequest,
			"nonce is required in the implicit/hybrid flow of OpenID Connect",
		)
	}

	return nil
}

type AuthzContext struct {
	API     *LauthAPI
	Gin     *gin.Context
	Request *AuthzRequest
	Report  *metrics.Context
}

func NewAuthzContext(api *LauthAPI, c *gin.Context) (*AuthzContext, *ErrorMessage) {
	m := metrics.StartAuthz(c)

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	req := new(AuthzRequest)
	if err := req.Bind(c); err != nil {
		err.Report(m)
		m.Close()
		return nil, err
	}

	m.Set("client_id", req.ClientID)
	m.Set("response_type", req.ResponseType)
	m.Set("scope", req.Scope)
	m.Set("prompt", req.Prompt)

	return &AuthzContext{
		API:     api,
		Gin:     c,
		Request: req,
		Report:  m,
	}, nil
}

func (ctx *AuthzContext) Close() error {
	return ctx.Report.Close()
}

func (ctx *AuthzContext) ErrorRedirect(msg *ErrorMessage) {
	msg.Report(ctx.Report)
	msg.Redirect(ctx.Gin)
}

func (ctx *AuthzContext) TrySSO(authorized bool) (proceed bool) {
	ctx.Report.Set("authn_by", "password")

	prompt := ParseStringSet(ctx.Request.Prompt)

	if prompt.Has("login") || prompt.Has("select_account") || ctx.API.Config.Expire.SSO <= 0 {
		return false
	}

	token, err := ctx.API.GetSSOToken(ctx.Gin)
	if err == nil {
		if ctx.Request.MaxAge <= 0 || ctx.Request.MaxAge > time.Now().Unix()-token.AuthTime {
			ctx.Report.Set("authn_by", "sso_token")
			ctx.Report.Set("username", token.Subject)

			if prompt.Has("consent") && !authorized {
				ctx.ShowConfirmPage(http.StatusOK, token.Subject)
				return true
			}

			ctx.SendTokens(token.Subject, time.Unix(token.AuthTime, 0))
			return true
		}
	} else if err != http.ErrNoCookie {
		ctx.API.DeleteSSOToken(ctx.Gin)
	}

	if prompt.Has("none") {
		ctx.Report.Set("authn_by", "sso_token")
		ctx.ErrorRedirect(ctx.Request.makeRedirectError(nil, "login_required", ""))
		return true
	}

	return false
}

func (ctx *AuthzContext) showPage(code int, authzOnly bool, initialUser, errorDescription string) {
	sessionToken, err := ctx.API.MakeLoginSession(ctx.Gin.ClientIP(), ctx.Request.ClientID)
	if err != nil {
		ctx.ErrorRedirect(ctx.Request.makeRedirectError(err, "server_error", "failed to create session"))
		return
	}

	client := ctx.API.Config.Clients[ctx.Request.ClientID]

	data := map[string]interface{}{
		"client": map[string]interface{}{
			"Name":    client.Name,
			"IconURL": client.IconURL,
		},
		"request":          ctx.Request,
		"initial_username": initialUser,
		"session_token":    sessionToken,
		"error":            errorDescription,
		"authz_only":       authzOnly,
	}
	ctx.Gin.HTML(code, "login.tmpl", data)
}

func (ctx *AuthzContext) ShowLoginPage(code int, initialUser string, errorDescription string) {
	ctx.Report.Continue()
	ctx.showPage(code, false, initialUser, errorDescription)
}

func (ctx *AuthzContext) ShowConfirmPage(code int, initialUser string) {
	ctx.Report.Continue()
	ctx.showPage(code, true, initialUser, "")
}

func (ctx *AuthzContext) makeCodeToken(subject string, authTime time.Time) (string, *ErrorMessage) {
	code, err := ctx.API.TokenManager.CreateCode(
		ctx.API.Config.Issuer,
		subject,
		ctx.Request.ClientID,
		ctx.Request.RedirectURI,
		ctx.Request.Scope,
		ctx.Request.Nonce,
		authTime,
		time.Duration(ctx.API.Config.Expire.Code),
	)
	if err != nil {
		return "", ctx.Request.makeRedirectError(err, ServerError, "failed to generate code")
	}
	return code, nil
}

func (ctx *AuthzContext) makeAccessToken(subject string, authTime time.Time) (string, *ErrorMessage) {
	token, err := ctx.API.TokenManager.CreateAccessToken(
		ctx.API.Config.Issuer,
		subject,
		ctx.Request.Scope,
		authTime,
		time.Duration(ctx.API.Config.Expire.Token),
	)
	if err != nil {
		return "", ctx.Request.makeRedirectError(err, ServerError, "failed to generate access_token")
	}
	return token, nil
}

func (ctx *AuthzContext) makeIDToken(subject string, authTime time.Time, code, accessToken string) (string, *ErrorMessage) {
	scope := ParseStringSet(ctx.Request.Scope)
	userinfo, errMsg := ctx.API.userinfo(subject, scope)
	if errMsg != nil {
		errMsg.RedirectURI, _ = url.Parse(ctx.Request.RedirectURI)
		return "", errMsg
	}

	token, err := ctx.API.TokenManager.CreateIDToken(
		ctx.API.Config.Issuer,
		subject,
		ctx.Request.ClientID,
		ctx.Request.Nonce,
		code,
		accessToken,
		userinfo,
		authTime,
		time.Duration(ctx.API.Config.Expire.Token),
	)
	if err != nil {
		return "", ctx.Request.makeRedirectError(err, ServerError, "failed to generate id_token")
	}

	return token, nil
}

func (ctx *AuthzContext) makeAuthzTokens(subject string, authTime time.Time) (*url.URL, *ErrorMessage) {
	resp := make(url.Values)

	if ctx.Request.State != "" {
		resp.Set("state", ctx.Request.State)
	}

	rt := ParseStringSet(ctx.Request.ResponseType)

	if rt.Has("code") {
		code, err := ctx.makeCodeToken(subject, authTime)
		if err != nil {
			return nil, err
		}
		resp.Set("code", code)
	}
	if rt.Has("token") {
		token, err := ctx.makeAccessToken(subject, authTime)
		if err != nil {
			return nil, err
		}
		resp.Set("token_type", "Bearer")
		resp.Set("access_token", token)
		resp.Set("scope", ctx.Request.Scope)
		resp.Set("expires_in", ctx.API.Config.Expire.Token.StrSeconds())
	}
	if rt.Has("id_token") {
		token, err := ctx.makeIDToken(subject, authTime, resp.Get("code"), resp.Get("access_token"))
		if err != nil {
			return nil, err
		}
		resp.Set("id_token", token)
		resp.Set("expires_in", ctx.API.Config.Expire.Token.StrSeconds())
	}

	redirectURI, _ := url.Parse(ctx.Request.RedirectURI)
	if rt.String() != "code" {
		redirectURI.Fragment = resp.Encode()
	} else {
		redirectURI.RawQuery = resp.Encode()
	}
	return redirectURI, nil
}

func (ctx *AuthzContext) SendTokens(subject string, authTime time.Time) {
	redirect, errMsg := ctx.makeAuthzTokens(subject, authTime)

	if errMsg != nil {
		ctx.ErrorRedirect(errMsg)
	} else {
		ctx.Report.Success()
		ctx.Gin.Redirect(http.StatusFound, redirect.String())
	}
}
