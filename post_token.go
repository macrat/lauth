package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

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
			Description: "only supported grant_type is authorization_code",
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

	code, err := api.JWTManager.ParseCode(req.Code)
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
	scope := ParseStringSet(code.Scope)
	scope.Add("openid")

	accessToken, err := api.JWTManager.CreateAccessToken(
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

	idToken, err := api.JWTManager.CreateIDToken(
		api.Config.Issuer,
		code.Subject,
		code.ClientID,
		code.Nonce,
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
