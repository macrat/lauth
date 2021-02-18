package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/errors"
	"github.com/macrat/lauth/metrics"
	"github.com/macrat/lauth/token"
)

type AuthzRequest struct {
	ResponseType string `form:"response_type" json:"response_type" xml:"response_type"`
	ClientID     string `form:"client_id"     json:"client_id"     xml:"client_id"`
	RedirectURI  string `form:"redirect_uri"  json:"redirect_uri"  xml:"redirect_uri"`
	Scope        string `form:"scope"         json:"scope"         xml:"scope"`
	State        string `form:"state"         json:"state"         xml:"state"`
	Nonce        string `form:"nonce"         json:"nonce"         xml:"nonce"`
	MaxAge       int64  `form:"max_age"       json:"max_age"       xml:"max_age"`
	Prompt       string `form:"prompt"        json:"prompt"        xml:"prompt"`

	// use only GET method
	LoginHint string `form:"login_hint" json:"login_hint" xml:"login_hint"`
	Request   string `form:"request"    json:"request"    xml:"request"`

	// use only POST method
	User     string `form:"username" json:"username" xml:"username"`
	Password string `form:"password" json:"password" xml:"password"`

	// not supported
	RequestURI string `form:"request_uri" json:"request_uri" xml:"request_uri"`

	RequestExpiresAt int64  `form:"-" json:"-" xml:"-"`
	RequestSubject   string `form:"-" json:"-" xml:"-"`
}

func (req *AuthzRequest) makeRedirectError(err error, reason errors.Reason, description string) *errors.Error {
	redirectURI, _ := url.Parse(req.RedirectURI)

	return &errors.Error{
		Err:          err,
		RedirectURI:  redirectURI,
		ResponseType: req.ResponseType,
		State:        req.State,
		Reason:       reason,
		Description:  description,
	}
}

func (req *AuthzRequest) makeNonRedirectError(err error, reason errors.Reason, description string) *errors.Error {
	return &errors.Error{
		Err:          err,
		ResponseType: req.ResponseType,
		State:        req.State,
		Reason:       reason,
		Description:  description,
	}
}

func (req *AuthzRequest) RequestObjectClaims() token.RequestObjectClaims {
	return token.RequestObjectClaims{
		ResponseType: req.ResponseType,
		ClientID:     req.ClientID,
		RedirectURI:  req.RedirectURI,
		Scope:        req.Scope,
		State:        req.State,
		Nonce:        req.Nonce,
		MaxAge:       req.MaxAge,
	}
}

type AuthzRequestUnmarshaller interface {
	GetRequest() *AuthzRequest
	PreProcess(api *LauthAPI) *errors.Error
}

type GetAuthzRequestUnmarshaller AuthzRequest

func (req *GetAuthzRequestUnmarshaller) GetRequest() *AuthzRequest {
	return (*AuthzRequest)(req)
}

func (req *GetAuthzRequestUnmarshaller) processRequestObject(api *LauthAPI) *errors.Error {
	if req.Request == "" {
		return nil
	}

	signKey := ""
	if c, ok := api.Config.Clients[req.ClientID]; ok {
		signKey = c.RequestKey
	}
	claims, err := api.TokenManager.ParseRequestObject(req.Request, signKey)
	if err != nil {
		return req.GetRequest().makeNonRedirectError(
			err,
			errors.InvalidRequestObject,
			"failed to decode or validation request object",
		)
	}
	req.RequestExpiresAt = claims.ExpiresAt
	req.RequestSubject = claims.Subject

	if err = claims.Validate(req.ClientID, api.Config.Issuer); err != nil {
		return req.GetRequest().makeNonRedirectError(
			err,
			errors.InvalidRequestObject,
			"failed to decode or validation request object",
		)
	}

	var mismatches []string

	if claims.ResponseType != "" && claims.ResponseType != req.ResponseType {
		mismatches = append(mismatches, "response_type")
	}

	if claims.ClientID != "" && claims.ClientID != req.ClientID {
		mismatches = append(mismatches, "client_id")
	}

	if claims.RedirectURI != "" {
		if req.RedirectURI != "" && claims.RedirectURI != req.RedirectURI {
			mismatches = append(mismatches, "redirect_uri")
		} else {
			req.RedirectURI = claims.RedirectURI
		}
	}

	if claims.Scope != "" {
		if req.Scope != "" && claims.Scope != req.Scope {
			mismatches = append(mismatches, "scope")
		} else {
			req.Scope = claims.Scope
		}
	}

	if claims.State != "" {
		if req.State != "" && claims.State != req.State {
			mismatches = append(mismatches, "state")
		} else {
			req.State = claims.State
		}
	}

	if claims.Nonce != "" {
		if req.Nonce != "" && claims.Nonce != req.Nonce {
			mismatches = append(mismatches, "nonce")
		} else {
			req.Nonce = claims.Nonce
		}
	}

	if claims.MaxAge != 0 {
		if req.MaxAge != 0 && claims.MaxAge != req.MaxAge {
			mismatches = append(mismatches, "max_age")
		} else {
			req.MaxAge = claims.MaxAge
		}
	}

	if claims.Prompt != "" {
		if req.Prompt != "" && claims.Prompt != req.Prompt {
			mismatches = append(mismatches, "prompt")
		} else {
			req.Prompt = claims.Prompt
		}
	}

	if claims.LoginHint != "" {
		if req.LoginHint != "" && claims.LoginHint != req.LoginHint {
			mismatches = append(mismatches, "login_hint")
		} else {
			req.LoginHint = claims.LoginHint
		}
	}

	if len(mismatches) == 0 {
		return nil
	}

	return req.GetRequest().makeRedirectError(
		nil,
		errors.InvalidRequestObject,
		fmt.Sprintf("mismatch query parameter and request object: %s", strings.Join(mismatches, ", ")),
	)
}

func (req *GetAuthzRequestUnmarshaller) validate(api *LauthAPI) *errors.Error {
	if req.RedirectURI == "" {
		return req.GetRequest().makeNonRedirectError(nil, errors.InvalidRequest, "redirect_uri is required")
	}

	if u, err := url.Parse(req.RedirectURI); err != nil {
		return req.GetRequest().makeNonRedirectError(err, errors.InvalidRequest, "redirect_uri is invalid format")
	} else if !u.IsAbs() {
		return req.GetRequest().makeNonRedirectError(err, errors.InvalidRequest, "redirect_uri is must be absolute URL")
	}

	if req.ClientID == "" {
		return req.GetRequest().makeNonRedirectError(nil, errors.InvalidClient, "client_id is required")
	}
	if client, ok := api.Config.Clients[req.ClientID]; !ok {
		return req.GetRequest().makeNonRedirectError(
			nil,
			errors.InvalidClient,
			"client_id is not registered",
		)
	} else if !client.RedirectURI.Match(req.RedirectURI) {
		return req.GetRequest().makeNonRedirectError(
			nil,
			errors.UnauthorizedClient,
			"redirect_uri is not registered",
		)
	}

	if req.RequestURI != "" {
		return req.GetRequest().makeRedirectError(
			nil,
			errors.RequestURINotSupported,
			"",
		)
	}

	rt := ParseStringSet(req.ResponseType)
	if rt.String() == "" {
		return req.GetRequest().makeRedirectError(
			nil,
			errors.UnsupportedResponseType,
			"response_type is required",
		)
	}
	if err := rt.Validate("response_type", []string{"code", "token", "id_token"}); err != nil {
		return req.GetRequest().makeRedirectError(
			err,
			errors.UnsupportedResponseType,
			err.Error(),
		)
	}
	if !api.Config.Clients[req.ClientID].AllowImplicitFlow && rt.String() != "code" {
		return req.GetRequest().makeRedirectError(
			nil,
			errors.UnsupportedResponseType,
			"implicit/hybrid flow is disallowed",
		)
	}

	prompt := ParseStringSet(req.Prompt)
	if prompt.Has("none") && (prompt.Has("login") || prompt.Has("select_account") || prompt.Has("consent")) {
		return req.GetRequest().makeRedirectError(
			nil,
			errors.InvalidRequest,
			"prompt=none can't use same time with login, select_account, or consent",
		)
	}

	if rt.Has("id_token") && req.Nonce == "" {
		return req.GetRequest().makeRedirectError(
			nil,
			errors.InvalidRequest,
			"nonce is required in the implicit/hybrid flow of OpenID Connect",
		)
	}

	return nil
}

func (req *GetAuthzRequestUnmarshaller) PreProcess(api *LauthAPI) *errors.Error {
	if err := req.processRequestObject(api); err != nil {
		return err
	}
	return req.validate(api)
}

type PostAuthzRequestUnmarshaller struct {
	Request  string `form:"request"  json:"request"  xml:"request"`
	User     string `form:"username" json:"username" xml:"username"`
	Password string `form:"password" json:"password" xml:"password"`

	claims token.RequestObjectClaims
}

func (req *PostAuthzRequestUnmarshaller) GetRequest() *AuthzRequest {
	return &AuthzRequest{
		ResponseType: req.claims.ResponseType,
		ClientID:     req.claims.ClientID,
		RedirectURI:  req.claims.RedirectURI,
		Scope:        req.claims.Scope,
		State:        req.claims.State,
		Nonce:        req.claims.Nonce,
		MaxAge:       req.claims.MaxAge,

		User:     req.User,
		Password: req.Password,

		RequestExpiresAt: req.claims.ExpiresAt,
		RequestSubject:   req.claims.Subject,
	}
}

func (req *PostAuthzRequestUnmarshaller) PreProcess(api *LauthAPI) *errors.Error {
	var err error
	req.claims, err = api.TokenManager.ParseRequestObject(req.Request, "")
	if err != nil {
		return req.GetRequest().makeNonRedirectError(
			err,
			errors.InvalidRequestObject,
			"failed to decode or validation request object",
		)
	}

	if err = req.claims.Validate(api.Config.Issuer.String(), api.Config.Issuer); err != nil {
		return req.GetRequest().makeNonRedirectError(
			err,
			errors.InvalidRequestObject,
			"failed to decode or validation request object",
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

func NewAuthzContext(api *LauthAPI, c *gin.Context) (*AuthzContext, *errors.Error) {
	m := metrics.StartAuthz(c)

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var unmarshaller AuthzRequestUnmarshaller
	if c.Request.Method == "GET" {
		unmarshaller = new(GetAuthzRequestUnmarshaller)
	} else {
		unmarshaller = new(PostAuthzRequestUnmarshaller)
	}
	if err := c.ShouldBind(unmarshaller); err != nil {
		e := &errors.Error{
			Err:         err,
			Reason:      errors.InvalidRequest,
			Description: "failed to parse request",
		}
		m.SetError(e)
		m.Close()
		return nil, e
	}

	if err := unmarshaller.PreProcess(api); err != nil {
		m.SetError(err)
		m.Close()
		return nil, err
	}

	req := unmarshaller.GetRequest()

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

func (ctx *AuthzContext) MakeRequestObject() (string, error) {
	expiresAt := time.Now().Add(time.Duration(ctx.API.Config.Expire.Login))

	if 0 < ctx.Request.RequestExpiresAt && ctx.Request.RequestExpiresAt < expiresAt.Unix() {
		expiresAt = time.Unix(ctx.Request.RequestExpiresAt, 0)
	}

	return ctx.API.TokenManager.CreateRequestObject(
		ctx.API.Config.Issuer,
		ctx.Gin.ClientIP(),
		ctx.Request.RequestObjectClaims(),
		expiresAt,
	)
}

func (ctx *AuthzContext) ErrorRedirect(err *errors.Error) {
	ctx.Report.SetError(err)
	errors.SendRedirect(ctx.Gin, err)
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

			if !authorized && (prompt.Has("consent") || !token.Authorized.Includes(ctx.Request.ClientID)) {
				ctx.ShowConfirmPage(http.StatusOK, token.Subject)
				return true
			}

			ctx.API.SetSSOToken(ctx.Gin, token.Subject, ctx.Request.ClientID, false)
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
	requestObject, err := ctx.MakeRequestObject()
	if err != nil {
		ctx.ErrorRedirect(ctx.Request.makeRedirectError(err, "server_error", "failed to create login session"))
		return
	}

	client := ctx.API.Config.Clients[ctx.Request.ClientID]

	data := map[string]interface{}{
		"client": map[string]interface{}{
			"ID":      ctx.Request.ClientID,
			"Name":    client.Name,
			"IconURL": client.IconURL,
		},
		"response_type":    ctx.Request.ResponseType,
		"request":          requestObject,
		"initial_username": initialUser,
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

func (ctx *AuthzContext) makeCodeToken(subject string, authTime time.Time) (string, *errors.Error) {
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
		return "", ctx.Request.makeRedirectError(err, errors.ServerError, "failed to generate code")
	}
	return code, nil
}

func (ctx *AuthzContext) makeAccessToken(subject string, authTime time.Time) (string, *errors.Error) {
	token, err := ctx.API.TokenManager.CreateAccessToken(
		ctx.API.Config.Issuer,
		subject,
		ctx.Request.Scope,
		authTime,
		time.Duration(ctx.API.Config.Expire.Token),
	)
	if err != nil {
		return "", ctx.Request.makeRedirectError(err, errors.ServerError, "failed to generate access_token")
	}
	return token, nil
}

func (ctx *AuthzContext) makeIDToken(subject string, authTime time.Time, code, accessToken string) (string, *errors.Error) {
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
		return "", ctx.Request.makeRedirectError(err, errors.ServerError, "failed to generate id_token")
	}

	return token, nil
}

func (ctx *AuthzContext) makeAuthzTokens(subject string, authTime time.Time) (*url.URL, *errors.Error) {
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
