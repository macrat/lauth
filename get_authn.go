package main

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

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

	c.HTML(http.StatusOK, "login.tmpl", gin.H{
		"config":  api.Config,
		"request": req,
	})
}
