package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type ErrorMessage struct {
	Err          error    `json:"-"`
	RedirectURI  *url.URL `json:"-"`
	ResponseType string   `json:"-"`
	State        string   `json:"state,omitempty"`
	Reason       string   `json:"error"`
	Description  string   `json:"error_description,omitempty"`
	ErrorURI     string   `json:"error_uri,omitempty"`
}

func (msg ErrorMessage) Unwrap() error {
	return msg.Err
}

func (msg ErrorMessage) Error() string {
	if msg.State == "" {
		return fmt.Sprintf("%s: %s", msg.Reason, msg.Description)
	} else {
		return fmt.Sprintf("%s(%s): %s", msg.Reason, msg.State, msg.Description)
	}
}

func (msg ErrorMessage) Redirect(c *gin.Context) {
	if msg.RedirectURI == nil || msg.RedirectURI.String() == "" {
		c.HTML(http.StatusBadRequest, "/error.tmpl", gin.H{
			"error": msg,
		})
		return
	}

	resp := make(url.Values)
	if msg.State != "" {
		resp.Set("state", msg.State)
	}

	resp.Set("error", msg.Reason)
	resp.Set("error_description", msg.Description)

	if msg.ResponseType != "code" {
		msg.RedirectURI.Fragment = resp.Encode()
	} else {
		msg.RedirectURI.RawQuery = resp.Encode()
	}
	c.Redirect(http.StatusFound, msg.RedirectURI.String())
}

type GetAuthnRequest struct {
	ResponseType string `form:"response_type" json:"response_type" xml:"response_type"`
	ClientID     string `form:"client_id"     json:"client_id"     xml:"client_id"`
	RedirectURI  string `form:"redirect_uri"  json:"redirect_uri"  xml:"redirect_uri"`
	Scope        string `form:"scope"         json:"scope"         xml:"scope"`
	State        string `form:"state"         json:"state"         xml:"state"`
	Nonce        string `form:"nonce"         json:"nonce"         xml:"nonce"`
	Prompt       string `form:"prompt"        json:"prompt"        xml:"prompt"`
	MaxAge       int64  `form:"max_age"       json:"max_age"       xml:"max_age"`
}

func (req *GetAuthnRequest) Bind(c *gin.Context) *ErrorMessage {
	err := c.ShouldBind(req)
	if err != nil {
		return &ErrorMessage{
			Err:         err,
			Reason:      "invalid_request",
			Description: "failed to parse request",
		}
	}
	return nil
}

func (req GetAuthnRequest) makeError(err error, reason, description string) *ErrorMessage {
	redirectURI, e2 := url.Parse(req.RedirectURI)
	if e2 != nil {
		redirectURI = nil
	}

	return &ErrorMessage{
		Err:         err,
		RedirectURI: redirectURI,
		State:       req.State,
		Reason:      reason,
		Description: description,
	}
}

func (req GetAuthnRequest) Validate() *ErrorMessage {
	if req.RedirectURI == "" {
		return req.makeError(nil, "invalid_redirect_uri", "redirect_uri is not set")
	}

	_, err := url.Parse(req.RedirectURI)
	if err != nil {
		return req.makeError(err, "invalid_redirect_uri", "redirect_uri is invalid format")
	}

	if req.ClientID == "" {
		return req.makeError(nil, "invalid_request", "client_id is required")
	}

	if err := ParseStringSet(req.ResponseType).Validate("response_type", []string{"code", "token", "id_token"}); err != nil {
		return req.makeError(
			err,
			"unsupported_response_type",
			err.Error(),
		)
	}

	return nil
}

func (req *GetAuthnRequest) BindAndValidate(c *gin.Context) *ErrorMessage {
	if err := req.Bind(c); err != nil {
		return err
	}
	return req.Validate()
}

type PostAuthnRequest struct {
	GetAuthnRequest

	User     string `form:"username" json:"username" xml:"username"`
	Password string `form:"password" json:"password" xml:"password"`
}

func (req *PostAuthnRequest) Bind(c *gin.Context) *ErrorMessage {
	err := c.ShouldBind(req)
	if err != nil {
		return &ErrorMessage{
			Err:         err,
			Reason:      "invalid_request",
			Description: "failed to parse request",
		}
	}
	return nil
}

func (req *PostAuthnRequest) BindAndValidate(c *gin.Context) *ErrorMessage {
	if err := req.Bind(c); err != nil {
		return err
	}
	return req.Validate()
}

type PostTokenRequest struct {
	GrantType string `form:"grant_type"   json:"grant_type"   xml:"grant_type"`
	Code      string `form:"code"         json:"code"         xml:"code"`
}

func (req *PostTokenRequest) Bind(c *gin.Context) *ErrorMessage {
	err := c.ShouldBind(req)
	if err != nil {
		return &ErrorMessage{
			Err:         err,
			Reason:      "invalid_request",
			Description: "failed to parse request",
		}
	}
	return nil
}

func (req PostTokenRequest) Validate() *ErrorMessage {
	if req.GrantType != "authorization_code" {
		return &ErrorMessage{
			Reason:      "unsupported_grant_type",
			Description: "not supported grant_type",
		}
	}

	return nil
}

func (req *PostTokenRequest) BindAndValidate(c *gin.Context) *ErrorMessage {
	if err := req.Bind(c); err != nil {
		return err
	}
	return req.Validate()
}

type GetUserInfoHeader struct {
	Authorization string `header:"Authorization"`
}

type LdapinAPI struct {
	Connector  LDAPConnector
	Config     LdapinConfig
	JWTManager JWTManager
}

func (api *LdapinAPI) GetConfiguration(c *gin.Context) {
	c.JSON(200, api.Config.OpenIDConfiguration())
}

func (api *LdapinAPI) GetAuthn(c *gin.Context) {
	var req GetAuthnRequest
	if err := (&req).BindAndValidate(c); err != nil {
		err.Redirect(c)
		return
	}

	if ParseStringSet(req.Prompt).Has("none") {
		ErrorMessage{
			Reason:      "login_required",
			Description: "prompt=none is not supported",
		}.Redirect(c)
		return
	}

	c.HTML(http.StatusOK, "/login.tmpl", gin.H{
		"config":  api.Config,
		"request": req,
	})
}

func (api *LdapinAPI) PostAuthn(c *gin.Context) {
	var req PostAuthnRequest
	if err := (&req).BindAndValidate(c); err != nil {
		err.Redirect(c)
		return
	}
	scope := ParseStringSet(req.Scope)
	scope.Add("openid")
	req.Scope = scope.String()

	if req.User == "" || req.Password == "" {
		c.HTML(http.StatusForbidden, "/login.tmpl", gin.H{
			"config":           api.Config,
			"request":          req.GetAuthnRequest,
			"initial_username": req.User,
			"error":            "missing_username_or_password",
		})
		return
	}

	conn, err := api.Connector.Connect()
	if err != nil {
		log.Print(err)
		req.makeError(err, "server_error", "failed to connecting LDAP server").Redirect(c)
		return
	}
	defer conn.Close()

	if err := conn.LoginTest(req.User, req.Password); err != nil {
		c.HTML(http.StatusForbidden, "/login.tmpl", gin.H{
			"config":           api.Config,
			"request":          req.GetAuthnRequest,
			"initial_username": req.User,
			"error":            "invalid_username_or_password",
		})
		return
	}

	resp := make(url.Values)

	if req.State != "" {
		resp.Set("state", req.State)
	}

	rt := ParseStringSet(req.ResponseType)

	if rt.Has("code") {
		code, err := api.JWTManager.CreateCode(
			api.Config.Issuer,
			req.User,
			req.ClientID,
			req.Scope,
			time.Now(),
			api.Config.CodeExpiresIn,
		)
		if err != nil {
			req.makeError(err, "server_error", "failed to generate code").Redirect(c)
			return
		}
		resp.Set("code", code)
	}
	if rt.Has("token") {
		token, err := api.JWTManager.CreateAccessToken(
			api.Config.Issuer,
			req.User,
			req.Scope,
			time.Now(),
			api.Config.TokenExpiresIn,
		)
		if err != nil {
			req.makeError(err, "server_error", "failed to generate code").Redirect(c)
			return
		}
		resp.Set("token_type", "Bearer")
		resp.Set("access_token", token)
		resp.Set("scope", req.Scope)
		resp.Set("expires_in", strconv.Itoa(int(api.Config.TokenExpiresIn.Seconds())))
	}
	if rt.Has("id_token") {
		token, err := api.JWTManager.CreateIDToken(
			api.Config.Issuer,
			req.User,
			req.ClientID,
			time.Now(),
			api.Config.TokenExpiresIn,
		)
		if err != nil {
			req.makeError(err, "server_error", "failed to generate code").Redirect(c)
			return
		}
		resp.Set("id_token", token)
		resp.Set("expires_in", strconv.Itoa(int(api.Config.TokenExpiresIn.Seconds())))
	}

	redirectURI, _ := url.Parse(req.RedirectURI)
	if rt.String() != "code" {
		redirectURI.Fragment = resp.Encode()
	} else {
		redirectURI.RawQuery = resp.Encode()
	}
	c.Redirect(http.StatusFound, redirectURI.String())
}

func (api *LdapinAPI) PostToken(c *gin.Context) {
	var req PostTokenRequest
	if err := (&req).BindAndValidate(c); err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	code, err := api.JWTManager.ParseCode(req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Err:    err,
			Reason: "invalid_grant",
		})
	}
	if err := code.Validate(api.Config.Issuer); err != nil {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Err:    err,
			Reason: "invalid_grant",
		})
	}
	scope := ParseStringSet(code.Scope)
	scope.Add("openid")

	accessToken, err := api.JWTManager.CreateAccessToken(
		api.Config.Issuer,
		code.Subject,
		scope.String(),
		time.Unix(code.AuthTime, 0),
		api.Config.TokenExpiresIn,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to generate access_token",
		})
	}

	idToken, err := api.JWTManager.CreateIDToken(
		api.Config.Issuer,
		code.Subject,
		code.ClientID,
		time.Unix(code.AuthTime, 0),
		api.Config.TokenExpiresIn,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to generate access_token",
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"token_type":   "Bearer",
		"access_token": accessToken,
		"id_token":     idToken,
		"expires_in":   api.Config.TokenExpiresIn,
		"scope":        code.Scope,
	})
}

func (api *LdapinAPI) GetUserInfo(c *gin.Context) {
	var header GetUserInfoHeader
	if err := c.ShouldBindHeader(&header); err != nil || !strings.HasPrefix(header.Authorization, "Bearer ") {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"bearer token is required\"")
		c.JSON(http.StatusForbidden, ErrorMessage{
			Reason:      "invalid_token",
			Description: "bearer token is required",
		})
		return
	}

	rawToken := strings.TrimSpace(header.Authorization[len("Bearer "):])
	token, err := api.JWTManager.ParseAccessToken(rawToken)
	if err == nil {
		err = token.Validate(api.Config.Issuer)
	}
	if err != nil {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"token is invalid\"")
		c.JSON(http.StatusForbidden, ErrorMessage{
			Err:         err,
			Reason:      "invalid_token",
			Description: "token is invalid",
		})
		return
	}

	conn, err := api.Connector.Connect()
	if err != nil {
		log.Print(err)
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Reason:      "server_error",
			Description: "failed to connecting LDAP server",
		})
		return
	}
	defer conn.Close()

	scope := ParseStringSet(token.Scope)
	attrs, err := conn.GetUserAttributes(token.Subject, api.Config.Scopes.AttributesFor(scope))
	if err == UserNotFoundError {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"token is invalid\"")
		c.JSON(http.StatusForbidden, ErrorMessage{
			Err:         err,
			Reason:      "invalid_token",
			Description: "user was not found or disabled",
		})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Reason:      "server_error",
			Description: "failed to get attributes",
		})
		return
	}

	maps := api.Config.Scopes.ClaimMapFor(scope)
	result := MappingClaims(attrs, maps)
	result["sub"] = token.Subject

	c.JSON(http.StatusOK, result)
}

func (api *LdapinAPI) GetCerts(c *gin.Context) {
	keys, err := api.JWTManager.JWKs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to get key informations",
		})
		return
	}

	c.JSON(http.StatusOK, keys)
}
