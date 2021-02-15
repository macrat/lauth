package api

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/errors"
	"github.com/macrat/lauth/metrics"
)

type LogoutRequest struct {
	IDTokenHint string `form:"id_token_hint"            json:"id_token_hint"            xml:"id_token_hint"`
	RedirectURI string `form:"post_logout_redirect_uri" json:"post_logout_redirect_uri" xml:"post_logout_redirect_uri"`
	State       string `form:"state"                    json:"state"                    xml:"state"`
}

func (req *LogoutRequest) Bind(c *gin.Context) *errors.Error {
	err := c.ShouldBind(req)
	if err != nil {
		return &errors.Error{
			Err:         err,
			Reason:      errors.InvalidRequest,
			Description: "failed to parse request",
		}
	}
	return nil
}

func (api *LauthAPI) Logout(c *gin.Context) {
	report := metrics.StartLogout(c)
	defer report.Close()

	var req LogoutRequest
	if e := (&req).Bind(c); e != nil {
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	}

	report.Set("redirect_uri", req.RedirectURI)

	if req.IDTokenHint == "" {
		e := &errors.Error{
			Reason:      errors.InvalidRequest,
			Description: "id_token_hint is required in this OP",
		}
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	}

	redirectURI, err := url.Parse(req.RedirectURI)
	if err != nil {
		e := &errors.Error{
			Err:         err,
			Reason:      errors.InvalidRequest,
			Description: "post_logout_redirect_uri is invalid format",
		}
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	}
	if req.RedirectURI != "" && !redirectURI.IsAbs() {
		e := &errors.Error{
			Reason:      errors.InvalidRequest,
			Description: "post_logout_redirect_uri is must be absolute URL",
		}
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	}

	idToken, err := api.TokenManager.ParseIDToken(req.IDTokenHint)
	if err != nil {
		e := &errors.Error{
			Err:         err,
			Reason:      errors.InvalidRequest,
			Description: "invalid id_token_hint",
		}
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	}
	report.Set("client_id", idToken.Audience)
	report.Set("username", idToken.Subject)

	if client, ok := api.Config.Clients[idToken.Audience]; !ok {
		e := &errors.Error{
			Reason:      errors.InvalidRequest,
			Description: "client is not registered",
		}
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	} else if req.RedirectURI != "" && !client.RedirectURI.Match(req.RedirectURI) {
		e := &errors.Error{
			Reason:      errors.InvalidRequest,
			Description: "post_logout_redirect_uri is not registered",
		}
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	}

	if idToken.Issuer != api.Config.Issuer.String() {
		e := &errors.Error{
			Reason:      errors.InvalidRequest,
			Description: "invalid id_token_hint",
		}
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	}

	ssoToken, err := api.GetSSOToken(c)
	if err != nil {
		e := &errors.Error{
			Err:         err,
			Reason:      errors.InvalidRequest,
			Description: "user not logged in",
		}
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	}
	if !ssoToken.Authorized.Includes(idToken.Audience) || idToken.Subject != ssoToken.Subject {
		e := &errors.Error{
			Reason:      errors.InvalidRequest,
			Description: "user not logged in",
		}
		report.SetError(e)
		errors.SendHTML(c, e)
		return
	}

	api.DeleteSSOToken(c)

	if req.RedirectURI == "" {
		c.HTML(http.StatusOK, "logout.tmpl", nil)
	} else {
		if req.State != "" {
			query := redirectURI.Query()
			query.Set("state", req.State)
			redirectURI.RawQuery = query.Encode()
		}
		c.Redirect(http.StatusFound, redirectURI.String())
	}
}
