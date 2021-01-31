package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/config"
	"github.com/macrat/ldapin/metrics"
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
			Reason:      InvalidRequest,
			Description: "failed to parse request",
		}
	}
	if u, p, ok := c.Request.BasicAuth(); ok {
		req.ClientID = u
		req.ClientSecret = p
	}
	return nil
}

func (req PostTokenRequest) Validate(conf *config.Config) *ErrorMessage {
	switch req.GrantType {
	case "authorization_code":
		if req.Code == "" {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "code is required when use authorization_code grant type",
			}
		}
		if req.RefreshToken != "" {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "can't set refresh_token when use authorization_code grant type",
			}
		}
	case "refresh_token":
		if req.RefreshToken == "" {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "refresh_token is required when use refresh_token grant type",
			}
		}
		if req.Code != "" {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "can't set code when use refresh_token grant type",
			}
		}
	default:
		return &ErrorMessage{
			Reason:      UnsupportedGrantType,
			Description: "supported grant_type is authorization_code or refresh_token",
		}
	}

	if req.ClientID == "" {
		if !conf.DisableClientAuth && req.GrantType != "refresh_token" {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "client_id is required",
			}
		} else if req.ClientSecret != "" {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "client_id is required if set client_secret",
			}
		}
	} else if req.ClientSecret == "" {
		if !conf.DisableClientAuth {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "client_secret is required",
			}
		}
	} else {
		client, ok := conf.Clients[req.ClientID]
		if !ok || client.Secret != req.ClientSecret {
			return &ErrorMessage{
				Reason: InvalidClient,
			}
		}
	}

	if req.GrantType == "authorization_code" {
		if req.RedirectURI == "" {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "redirect_uri is required",
			}
		} else if u, err := url.Parse(req.RedirectURI); err != nil {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "redirect_uri is invalid format",
			}
		} else if !u.IsAbs() {
			return &ErrorMessage{
				Reason:      InvalidRequest,
				Description: "redirect_uri is must be absolute URL",
			}
		}
	}

	return nil
}

func (req *PostTokenRequest) BindAndValidate(c *gin.Context, conf *config.Config) *ErrorMessage {
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

func (api *LdapinAPI) postTokenWithCode(c *gin.Context, req PostTokenRequest) (*PostTokenResponse, *ErrorMessage) {
	code, err := api.TokenManager.ParseCode(req.Code)
	if err != nil {
		return nil, &ErrorMessage{
			Err:    err,
			Reason: InvalidGrant,
		}
	}
	if err := code.Validate(api.Config.Issuer); err != nil {
		return nil, &ErrorMessage{
			Err:    err,
			Reason: InvalidGrant,
		}
	}

	if req.ClientID != "" && req.ClientID != code.ClientID {
		return nil, &ErrorMessage{
			Reason: InvalidGrant,
		}
	}

	if req.RedirectURI != code.RedirectURI {
		return nil, &ErrorMessage{
			Reason: InvalidGrant,
		}
	}

	scope := ParseStringSet(code.Scope)

	accessToken, err := api.TokenManager.CreateAccessToken(
		api.Config.Issuer,
		code.Subject,
		scope.String(),
		time.Unix(code.AuthTime, 0),
		time.Duration(api.Config.Expire.Token),
	)
	if err != nil {
		return nil, &ErrorMessage{
			Err:         err,
			Reason:      ServerError,
			Description: "failed to generate access_token",
		}
	}

	var idToken string
	if scope.Has("openid") {
		userinfo, err := api.userinfo(code.Subject, scope)
		if err != nil {
			return nil, &ErrorMessage{
				Err:         err,
				Reason:      ServerError,
				Description: "failed to get user info",
			}
		}

		idToken, err = api.TokenManager.CreateIDToken(
			api.Config.Issuer,
			code.Subject,
			code.ClientID,
			code.Nonce,
			req.Code,
			accessToken,
			userinfo,
			time.Unix(code.AuthTime, 0),
			time.Duration(api.Config.Expire.Token),
		)
		if err != nil {
			return nil, &ErrorMessage{
				Err:         err,
				Reason:      ServerError,
				Description: "failed to generate access_token",
			}
		}
	}

	refreshToken := ""
	if api.Config.Expire.Refresh > 0 {
		refreshToken, err = api.TokenManager.CreateRefreshToken(
			api.Config.Issuer,
			code.Subject,
			code.ClientID,
			code.Scope,
			code.Nonce,
			time.Unix(code.AuthTime, 0),
			time.Duration(api.Config.Expire.Refresh),
		)
		if err != nil {
			return nil, &ErrorMessage{
				Err:         err,
				Reason:      ServerError,
				Description: "failed to generate refresh_token",
			}
		}
	}

	return &PostTokenResponse{
		TokenType:    "Bearer",
		AccessToken:  accessToken,
		IDToken:      idToken,
		ExpiresIn:    api.Config.Expire.Token.IntSeconds(),
		Scope:        code.Scope,
		RefreshToken: refreshToken,
	}, nil
}

func (api *LdapinAPI) postTokenWithRefreshToken(c *gin.Context, req PostTokenRequest) (*PostTokenResponse, *ErrorMessage) {
	refreshToken, err := api.TokenManager.ParseRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, &ErrorMessage{
			Err:    err,
			Reason: InvalidGrant,
		}
	}
	if err := refreshToken.Validate(api.Config.Issuer); err != nil {
		return nil, &ErrorMessage{
			Err:    err,
			Reason: InvalidGrant,
		}
	}

	if req.ClientID != "" && req.ClientID != refreshToken.ClientID {
		return nil, &ErrorMessage{
			Reason: InvalidGrant,
		}
	}

	accessToken, err := api.TokenManager.CreateAccessToken(
		api.Config.Issuer,
		refreshToken.Subject,
		refreshToken.Scope,
		time.Unix(refreshToken.AuthTime, 0),
		time.Duration(api.Config.Expire.Token),
	)
	if err != nil {
		return nil, &ErrorMessage{
			Err:         err,
			Reason:      ServerError,
			Description: "failed to generate access_token",
		}
	}

	scope := ParseStringSet(refreshToken.Scope)
	var idToken string
	if scope.Has("openid") {
		userinfo, err := api.userinfo(refreshToken.Subject, scope)
		if err != nil {
			return nil, &ErrorMessage{
				Err:         err,
				Reason:      ServerError,
				Description: "failed to get user info",
			}
		}

		idToken, err = api.TokenManager.CreateIDToken(
			api.Config.Issuer,
			refreshToken.Subject,
			refreshToken.ClientID,
			refreshToken.Nonce,
			"",
			accessToken,
			userinfo,
			time.Unix(refreshToken.AuthTime, 0),
			time.Duration(api.Config.Expire.Token),
		)
		if err != nil {
			return nil, &ErrorMessage{
				Err:         err,
				Reason:      ServerError,
				Description: "failed to generate access_token",
			}
		}
	}

	return &PostTokenResponse{
		TokenType:   "Bearer",
		AccessToken: accessToken,
		IDToken:     idToken,
		ExpiresIn:   api.Config.Expire.Token.IntSeconds(),
		Scope:       refreshToken.Scope,
	}, nil
}

func (api *LdapinAPI) PostToken(c *gin.Context) {
	report := metrics.StartPostToken()
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var req PostTokenRequest
	if err := (&req).BindAndValidate(c, api.Config); err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	report.Set("grant_type", req.GrantType)
	report.Set("client_id", req.ClientID)

	var resp *PostTokenResponse
	var err *ErrorMessage
	if req.GrantType == "authorization_code" {
		resp, err = api.postTokenWithCode(c, req)
	} else {
		resp, err = api.postTokenWithRefreshToken(c, req)
	}
	if err != nil {
		err.Report(report)
		err.JSON(c)
	} else if resp != nil {
		report.Set("scope", resp.Scope)
		c.JSON(http.StatusOK, resp)
	}
}
