package api

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/metrics"
)

type LogoutRequest struct {
	IDTokenHint string `form:"id_token_hint"            json:"id_token_hint"            xml:"id_token_hint"`
	RedirectURI string `form:"post_logout_redirect_uri" json:"post_logout_redirect_uri" xml:"post_logout_redirect_uri"`
	State       string `form:"state"                    json:"state"                    xml:"state"`
}

func (req *LogoutRequest) Bind(c *gin.Context) *ErrorMessage {
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

func (api *LauthAPI) Logout(c *gin.Context) {
	report := metrics.StartLogout(c)
	defer report.Close()

	var req LogoutRequest
	if msg := (&req).Bind(c); msg != nil {
		msg.Report(report)
		msg.HTML(c)
		return
	}

	report.Set("redirect_uri", req.RedirectURI)

	if req.IDTokenHint == "" {
		msg := ErrorMessage{
			Reason:      InvalidRequest,
			Description: "id_token_hint is required in this OP",
		}
		msg.Report(report)
		msg.HTML(c)
		return
	}

	redirectURI, err := url.Parse(req.RedirectURI)
	if err != nil {
		msg := ErrorMessage{
			Err:         err,
			Reason:      InvalidRequest,
			Description: "post_logout_redirect_uri is invalid format",
		}
		msg.Report(report)
		msg.HTML(c)
		return
	}
	if req.RedirectURI != "" && !redirectURI.IsAbs() {
		msg := ErrorMessage{
			Reason:      InvalidRequest,
			Description: "post_logout_redirect_uri is must be absolute URL",
		}
		msg.Report(report)
		msg.HTML(c)
		return
	}

	idToken, err := api.TokenManager.ParseIDToken(req.IDTokenHint)
	if err != nil {
		msg := ErrorMessage{
			Err:         err,
			Reason:      InvalidRequest,
			Description: "invalid id_token_hint",
		}
		msg.Report(report)
		msg.HTML(c)
		return
	}
	report.Set("client_id", idToken.Audience)
	report.Set("username", idToken.Subject)

	if client, ok := api.Config.Clients[idToken.Audience]; !ok {
		msg := ErrorMessage{
			Reason:      InvalidRequest,
			Description: "client is not registered",
		}
		msg.Report(report)
		msg.HTML(c)
		return
	} else if req.RedirectURI != "" && !client.RedirectURI.Match(req.RedirectURI) {
		msg := ErrorMessage{
			Reason:      InvalidRequest,
			Description: "post_logout_redirect_uri is not registered",
		}
		msg.Report(report)
		msg.HTML(c)
		return
	}

	if idToken.Issuer != api.Config.Issuer.String() {
		msg := ErrorMessage{
			Reason:      InvalidRequest,
			Description: "invalid id_token_hint",
		}
		msg.Report(report)
		msg.HTML(c)
		return
	}

	ssoToken, err := api.GetSSOToken(c)
	if err != nil {
		msg := ErrorMessage{
			Err:         err,
			Reason:      InvalidRequest,
			Description: "user not logged in",
		}
		msg.Report(report)
		msg.HTML(c)
		return
	}
	if !ssoToken.Authorized.Includes(idToken.Audience) || idToken.Subject != ssoToken.Subject {
		msg := ErrorMessage{
			Reason:      InvalidRequest,
			Description: "user not logged in",
		}
		msg.Report(report)
		msg.HTML(c)
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
