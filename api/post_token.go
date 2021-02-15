package api

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/errors"
	"github.com/macrat/lauth/metrics"
	"github.com/macrat/lauth/secret"
)

type PostTokenRequest struct {
	GrantType    string `form:"grant_type"    json:"grant_type"    xml:"grant_type"`
	Code         string `form:"code"          json:"code"          xml:"code"`
	RefreshToken string `form:"refresh_token" json:"refresh_token" xml:"refresh_token"`
	ClientID     string `form:"client_id"     json:"client_id"     xml:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret" xml:"client_secret"`
	RedirectURI  string `form:"redirect_uri"  json:"redirect_uri"  xml:"redirect_uri"`
}

func (req *PostTokenRequest) Bind(c *gin.Context) *errors.Error {
	err := c.ShouldBind(req)
	if err != nil {
		return &errors.Error{
			Err:         err,
			Reason:      errors.InvalidRequest,
			Description: "failed to parse request",
		}
	}
	if u, p, ok := c.Request.BasicAuth(); ok {
		req.ClientID = u
		req.ClientSecret = p
	}
	return nil
}

func (req PostTokenRequest) Validate(conf *config.Config) *errors.Error {
	switch req.GrantType {
	case "authorization_code":
		if req.Code == "" {
			return &errors.Error{
				Reason:      errors.InvalidRequest,
				Description: "code is required when use authorization_code grant type",
			}
		}
		if req.RefreshToken != "" {
			return &errors.Error{
				Reason:      errors.InvalidRequest,
				Description: "can't set refresh_token when use authorization_code grant type",
			}
		}
	case "refresh_token":
		if req.RefreshToken == "" {
			return &errors.Error{
				Reason:      errors.InvalidRequest,
				Description: "refresh_token is required when use refresh_token grant type",
			}
		}
		if req.Code != "" {
			return &errors.Error{
				Reason:      errors.InvalidRequest,
				Description: "can't set code when use refresh_token grant type",
			}
		}
	default:
		return &errors.Error{
			Reason:      errors.UnsupportedGrantType,
			Description: "supported grant_type is authorization_code or refresh_token",
		}
	}

	if req.ClientID == "" {
		return &errors.Error{
			Reason:      errors.InvalidRequest,
			Description: "client_id is required",
		}
	} else if req.ClientSecret == "" {
		return &errors.Error{
			Reason:      errors.InvalidRequest,
			Description: "client_secret is required",
		}
	} else {
		client, ok := conf.Clients[req.ClientID]
		if !ok {
			return &errors.Error{Reason: errors.InvalidClient}
		} else if err := secret.Compare(client.Secret, req.ClientSecret); err != nil {
			return &errors.Error{Err: err, Reason: errors.InvalidClient}
		}
	}

	if req.GrantType == "authorization_code" {
		if req.RedirectURI == "" {
			return &errors.Error{
				Reason:      errors.InvalidRequest,
				Description: "redirect_uri is required",
			}
		} else if u, err := url.Parse(req.RedirectURI); err != nil {
			return &errors.Error{
				Reason:      errors.InvalidRequest,
				Description: "redirect_uri is invalid format",
			}
		} else if !u.IsAbs() {
			return &errors.Error{
				Reason:      errors.InvalidRequest,
				Description: "redirect_uri is must be absolute URL",
			}
		}
	}

	return nil
}

func (req *PostTokenRequest) BindAndValidate(c *gin.Context, conf *config.Config) *errors.Error {
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

func (api *LauthAPI) postTokenWithCode(c *gin.Context, req PostTokenRequest, report *metrics.Context) (*PostTokenResponse, *errors.Error) {
	code, err := api.TokenManager.ParseCode(req.Code)
	if err != nil {
		return nil, &errors.Error{
			Err:    err,
			Reason: errors.InvalidGrant,
		}
	}
	report.Set("username", code.Subject)
	if err := code.Validate(api.Config.Issuer); err != nil {
		return nil, &errors.Error{
			Err:    err,
			Reason: errors.InvalidGrant,
		}
	}

	if req.ClientID != code.ClientID {
		return nil, &errors.Error{
			Err:    fmt.Errorf("mismatch client_id"),
			Reason: errors.InvalidGrant,
		}
	}

	if req.RedirectURI != code.RedirectURI {
		return nil, &errors.Error{
			Err:    fmt.Errorf("mismatch redirect_uri"),
			Reason: errors.InvalidGrant,
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
		return nil, &errors.Error{
			Err:         err,
			Reason:      errors.ServerError,
			Description: "failed to generate access_token",
		}
	}

	var idToken string
	if scope.Has("openid") {
		userinfo, errMsg := api.userinfo(code.Subject, scope)
		if err != nil {
			return nil, errMsg
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
			return nil, &errors.Error{
				Err:         err,
				Reason:      errors.ServerError,
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
			return nil, &errors.Error{
				Err:         err,
				Reason:      errors.ServerError,
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

func (api *LauthAPI) postTokenWithRefreshToken(c *gin.Context, req PostTokenRequest, report *metrics.Context) (*PostTokenResponse, *errors.Error) {
	refreshToken, err := api.TokenManager.ParseRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, &errors.Error{
			Err:    err,
			Reason: errors.InvalidGrant,
		}
	}
	report.Set("username", refreshToken.Subject)
	if err := refreshToken.Validate(api.Config.Issuer); err != nil {
		return nil, &errors.Error{
			Err:    err,
			Reason: errors.InvalidGrant,
		}
	}

	if req.ClientID != refreshToken.ClientID {
		return nil, &errors.Error{
			Err:    fmt.Errorf("mismatch client_id"),
			Reason: errors.InvalidGrant,
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
		return nil, &errors.Error{
			Err:         err,
			Reason:      errors.ServerError,
			Description: "failed to generate access_token",
		}
	}

	scope := ParseStringSet(refreshToken.Scope)
	var idToken string
	if scope.Has("openid") {
		userinfo, errMsg := api.userinfo(refreshToken.Subject, scope)
		if err != nil {
			return nil, errMsg
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
			return nil, &errors.Error{
				Err:         err,
				Reason:      errors.ServerError,
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

func (api *LauthAPI) PostToken(c *gin.Context) {
	report := metrics.StartToken(c)
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var req PostTokenRequest
	if err := (&req).BindAndValidate(c, api.Config); err != nil {
		report.Set("grant_type", req.GrantType)
		report.Set("client_id", req.ClientID)
		report.SetError(err)
		c.JSON(http.StatusBadRequest, err)
		return
	}

	report.Set("grant_type", req.GrantType)
	report.Set("client_id", req.ClientID)

	var resp *PostTokenResponse
	var err *errors.Error
	if req.GrantType == "authorization_code" {
		resp, err = api.postTokenWithCode(c, req, report)
	} else {
		resp, err = api.postTokenWithRefreshToken(c, req, report)
	}
	if err != nil {
		report.SetError(err)
		errors.SendJSON(c, err)
	} else if resp != nil {
		report.Set("scope", resp.Scope)
		report.Success()
		c.JSON(http.StatusOK, resp)
	}
}
