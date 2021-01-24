package main

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

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
		c.HTML(http.StatusForbidden, "login.tmpl", gin.H{
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
		c.HTML(http.StatusForbidden, "login.tmpl", gin.H{
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
			time.Duration(api.Config.TTL.Code),
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
			time.Duration(api.Config.TTL.Token),
		)
		if err != nil {
			req.makeError(err, "server_error", "failed to generate access_token").Redirect(c)
			return
		}
		resp.Set("token_type", "Bearer")
		resp.Set("access_token", token)
		resp.Set("scope", req.Scope)
		resp.Set("expires_in", api.Config.TTL.Token.StrSeconds())
	}
	if rt.Has("id_token") {
		token, err := api.JWTManager.CreateIDToken(
			api.Config.Issuer,
			req.User,
			req.ClientID,
			time.Now(),
			time.Duration(api.Config.TTL.Token),
		)
		if err != nil {
			req.makeError(err, "server_error", "failed to generate id_token").Redirect(c)
			return
		}
		resp.Set("id_token", token)
		resp.Set("expires_in", api.Config.TTL.Token.StrSeconds())
	}

	redirectURI, _ := url.Parse(req.RedirectURI)
	if rt.String() != "code" {
		redirectURI.Fragment = resp.Encode()
	} else {
		redirectURI.RawQuery = resp.Encode()
	}
	c.Redirect(http.StatusFound, redirectURI.String())
}
