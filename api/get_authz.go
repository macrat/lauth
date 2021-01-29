package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/config"
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
}

func (req *GetAuthzRequest) Bind(c *gin.Context) *ErrorMessage {
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

func (req GetAuthzRequest) makeError(err error, reason, description string) *ErrorMessage {
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

func (req GetAuthzRequest) Validate(config *config.LdapinConfig) *ErrorMessage {
	if req.RedirectURI == "" {
		return req.makeError(nil, "invalid_request", "redirect_uri is required")
	}

	if u, err := url.Parse(req.RedirectURI); err != nil {
		return req.makeError(err, "invalid_request", "redirect_uri is invalid format")
	} else if !u.IsAbs() {
		return req.makeError(err, "invalid_request", "redirect_uri is must be absolute URL")
	}

	if req.ClientID == "" {
		return req.makeError(nil, "invalid_request", "client_id is required")
	}
	if client, ok := config.Clients[req.ClientID]; !ok {
		if !config.DisableClientAuth {
			return req.makeError(
				nil,
				"unauthorized_client",
				"client_id is not registered",
			)
		}
	} else if !client.RedirectURI.Match(req.RedirectURI) {
		return req.makeError(
			nil,
			"invalid_request",
			"redirect_uri is not registered",
		)
	}

	rt := ParseStringSet(req.ResponseType)
	if rt.String() == "" {
		return req.makeError(
			nil,
			"unsupported_response_type",
			"response_type is required",
		)
	}
	if err := rt.Validate("response_type", []string{"code", "token", "id_token"}); err != nil {
		return req.makeError(
			err,
			"unsupported_response_type",
			err.Error(),
		)
	}
	if !config.AllowImplicitFlow && rt.String() != "code" {
		return req.makeError(
			nil,
			"unsupported_response_type",
			"implicit/hybrid flow is disallowed in this server",
		)
	}

	return nil
}

func (req *GetAuthzRequest) BindAndValidate(c *gin.Context, config *config.LdapinConfig) *ErrorMessage {
	if err := req.Bind(c); err != nil {
		return err
	}
	return req.Validate(config)
}

func (api *LdapinAPI) GetAuthz(c *gin.Context) {
	var req GetAuthzRequest
	if err := (&req).BindAndValidate(c, api.Config); err != nil {
		err.Redirect(c)
		return
	}

	prompt := ParseStringSet(req.Prompt)

	if !prompt.Has("login") && !prompt.Has("consent") && !prompt.Has("select_account") && *api.Config.TTL.SSO > 0 {
		if token, err := c.Cookie("token"); err == nil {
			issuer := api.Config.Issuer
			secure := issuer.Scheme == "https"
			if idToken, err := api.TokenManager.ParseIDToken(token); err != nil || idToken.Validate(issuer, issuer.String()) != nil {
				c.SetCookie("token", "", 0, "/", issuer.Host, secure, true)
			} else if req.MaxAge <= 0 || req.MaxAge > time.Now().Unix()-idToken.AuthTime {
				redirect, errMsg := api.makeAuthzTokens(req, idToken.Subject, time.Unix(idToken.AuthTime, 0))
				if errMsg != nil {
					errMsg.Redirect(c)
				} else {
					c.Redirect(http.StatusFound, redirect.String())
				}
				return
			}
		}
	}

	if ParseStringSet(req.Prompt).Has("none") {
		req.makeError(
			nil,
			"login_required",
			"",
		).Redirect(c)
		return
	}

	c.HTML(http.StatusOK, "login.tmpl", gin.H{
		"endpoints": api.Config.EndpointPaths(),
		"config":    api.Config,
		"request":   req,
	})
}
