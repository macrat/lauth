package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/config"
)

type PostTokenRequest struct {
	GrantType    string `form:"grant_type"    json:"grant_type"    xml:"grant_type"`
	Code         string `form:"code"          json:"code"          xml:"code"`
	RefreshToken string `form:"refresh_token" json:"refresh_token" xml:"refresh_token"`
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

func (req PostTokenRequest) Validate(conf *config.LdapinConfig) *ErrorMessage {
	switch req.GrantType {
	case "authorization_code":
		if req.Code == "" {
			return &ErrorMessage{
				Reason:      "invalid_request",
				Description: "code is required when use authorization_code grant type",
			}
		}
		if req.RefreshToken != "" {
			return &ErrorMessage{
				Reason:      "invalid_request",
				Description: "can't set refresh_token when use authorization_code grant type",
			}
		}
	case "refresh_token":
		if req.RefreshToken == "" {
			return &ErrorMessage{
				Reason:      "invalid_request",
				Description: "refresh_token is required when use refresh_token grant type",
			}
		}
		if req.Code != "" {
			return &ErrorMessage{
				Reason:      "invalid_request",
				Description: "can't set code when use refresh_token grant type",
			}
		}
	default:
		return &ErrorMessage{
			Reason:      "unsupported_grant_type",
			Description: "supported grant_type is authorization_code or refresh_token",
		}
	}

	if req.ClientID == "" {
		if !conf.DisableClientAuth && req.GrantType != "refresh_token" {
			return &ErrorMessage{
				Reason:      "invalid_request",
				Description: "client_id is required",
			}
		} else if req.ClientSecret != "" {
			return &ErrorMessage{
				Reason:      "invalid_request",
				Description: "client_id is required if set client_secret",
			}
		}
	} else if req.ClientSecret == "" {
		if !conf.DisableClientAuth {
			return &ErrorMessage{
				Reason:      "invalid_request",
				Description: "client_secret is required",
			}
		}
	} else {
		client, ok := conf.Clients[req.ClientID]
		if !ok || client.Secret != req.ClientSecret {
			return &ErrorMessage{
				Reason: "unauthorized_client",
			}
		}
	}

	if req.GrantType == "authorization_code" {
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
	}

	return nil
}

func (req *PostTokenRequest) BindAndValidate(c *gin.Context, conf *config.LdapinConfig) *ErrorMessage {
	if err := req.Bind(c); err != nil {
		return err
	}
	return req.Validate(conf)
}

type PostTokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"string"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (api *LdapinAPI) postTokenWithCode(c *gin.Context, req PostTokenRequest) {
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

	userinfo, err := api.userinfo(code.Subject, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to get user info",
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
		userinfo,
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

	refreshToken, err := api.TokenManager.CreateRefreshToken(
		api.Config.Issuer,
		code.Subject,
		code.ClientID,
		code.Scope,
		code.Nonce,
		time.Unix(code.AuthTime, 0),
		time.Duration(api.Config.TTL.Refresh),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to generate refresh_token",
		})
		return
	}

	c.JSON(http.StatusOK, PostTokenResponse{
		TokenType:    "Bearer",
		AccessToken:  accessToken,
		IDToken:      idToken,
		ExpiresIn:    api.Config.TTL.Token.IntSeconds(),
		Scope:        code.Scope,
		RefreshToken: refreshToken,
	})
}

func (api *LdapinAPI) postTokenWithRefreshToken(c *gin.Context, req PostTokenRequest) {
	refreshToken, err := api.TokenManager.ParseRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Err:    err,
			Reason: "invalid_grant",
		})
		return
	}
	if err := refreshToken.Validate(api.Config.Issuer); err != nil {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Err:    err,
			Reason: "invalid_grant",
		})
		return
	}

	if req.ClientID != "" && req.ClientID != refreshToken.ClientID {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Reason: "invalid_grant",
		})
		return
	}

	accessToken, err := api.TokenManager.CreateAccessToken(
		api.Config.Issuer,
		refreshToken.Subject,
		refreshToken.Scope,
		time.Unix(refreshToken.AuthTime, 0),
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

	scope := ParseStringSet(refreshToken.Scope)
	userinfo, err := api.userinfo(refreshToken.Subject, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to get user info",
		})
		return
	}

	idToken, err := api.TokenManager.CreateIDToken(
		api.Config.Issuer,
		refreshToken.Subject,
		refreshToken.ClientID,
		refreshToken.Nonce,
		"",
		accessToken,
		userinfo,
		time.Unix(refreshToken.AuthTime, 0),
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
		Scope:       refreshToken.Scope,
	})
}

func (api *LdapinAPI) PostToken(c *gin.Context) {
	var req PostTokenRequest
	if err := (&req).BindAndValidate(c, api.Config); err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	if req.GrantType == "authorization_code" {
		api.postTokenWithCode(c, req)
	} else {
		api.postTokenWithRefreshToken(c, req)
	}
}
