package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

type PostTokenRequest struct {
	GrantType    string `form:"grant_type"    json:"grant_type"    xml:"grant_type"`
	Code         string `form:"code"          json:"code"          xml:"code"`
	ClientID     string `form:"client_id"     json:"client_id"     xml:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret" xml:"client_secret"`
	RedirectURI  string `form:"redirect_uri"  json:"redirect_uri"  xml:"redirect_uri"`
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
			Description: "only supported grant_type is authorization_code",
		}
	}

	if req.Code == "" {
		return &ErrorMessage{
			Reason:      "invalid_request",
			Description: "code is required",
		}
	}

	if req.RedirectURI == "" {
		return &ErrorMessage{
			Reason:      "invalid_request",
			Description: "redirect_uri is required",
		}
	} else if u, err := url.Parse(req.RedirectURI); err != nil {
		return &ErrorMessage{
			Reason:      "invalid_request",
			Description: "redirect_uri is invalid format",
		}
	} else if !u.IsAbs() {
		return &ErrorMessage{
			Reason:      "invalid_request",
			Description: "redirect_uri is must be absolute URL",
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

type PostTokenResponse struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"string"`
}

func (api *LdapinAPI) PostToken(c *gin.Context) {
	var req PostTokenRequest
	if err := (&req).BindAndValidate(c); err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	if req.ClientID == "" {
		if !api.Config.DisableClientAuth {
			c.JSON(http.StatusBadRequest, ErrorMessage{
				Reason:      "invalid_request",
				Description: "client_id is required",
			})
			return
		} else if req.ClientSecret != "" {
			c.JSON(http.StatusBadRequest, ErrorMessage{
				Reason:      "invalid_request",
				Description: "client_id is required if set client_secret",
			})
			return
		}
	} else if req.ClientSecret == "" {
		if !api.Config.DisableClientAuth {
			c.JSON(http.StatusBadRequest, ErrorMessage{
				Reason:      "invalid_request",
				Description: "client_secret is required",
			})
			return
		}
	} else {
		client, ok := api.Config.Clients[req.ClientID]
		if !ok || client.Secret != req.ClientSecret {
			c.JSON(http.StatusBadRequest, ErrorMessage{
				Reason: "unauthorized_client",
			})
			return
		}
	}

	code, err := api.TokenManager.ParseCode(req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Err:    err,
			Reason: "invalid_grant",
		})
		return
	}
	if err := code.Validate(api.Config.Issuer); err != nil {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Err:    err,
			Reason: "invalid_grant",
		})
		return
	}

	if req.ClientID != "" && req.ClientID != code.ClientID {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Reason: "invalid_grant",
		})
		return
	}

	if req.RedirectURI != code.RedirectURI {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Reason:      "invalid_request",
			Description: "redirect_uri is miss match",
		})
		return
	}

	scope := ParseStringSet(code.Scope)
	scope.Add("openid")

	accessToken, err := api.TokenManager.CreateAccessToken(
		api.Config.Issuer,
		code.Subject,
		scope.String(),
		time.Unix(code.AuthTime, 0),
		time.Duration(api.Config.TTL.Token),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to generate access_token",
		})
		return
	}

	idToken, err := api.TokenManager.CreateIDToken(
		api.Config.Issuer,
		code.Subject,
		code.ClientID,
		code.Nonce,
		req.Code,
		accessToken,
		time.Unix(code.AuthTime, 0),
		time.Duration(api.Config.TTL.Token),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to generate access_token",
		})
		return
	}

	c.JSON(http.StatusOK, PostTokenResponse{
		TokenType:   "Bearer",
		AccessToken: accessToken,
		IDToken:     idToken,
		ExpiresIn:   api.Config.TTL.Token.IntSeconds(),
		Scope:       code.Scope,
	})
}
