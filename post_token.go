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
			Description: "not supported grant_type",
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
	}
	if err := code.Validate(api.Config.Issuer); err != nil {
		c.JSON(http.StatusBadRequest, ErrorMessage{
			Err:    err,
			Reason: "invalid_grant",
		})
	}
	scope := ParseStringSet(code.Scope)
	scope.Add("openid")

	accessToken, err := api.JWTManager.CreateAccessToken(
		api.Config.Issuer,
		code.Subject,
		scope.String(),
		time.Unix(code.AuthTime, 0),
		api.Config.TokenExpiresIn,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to generate access_token",
		})
	}

	idToken, err := api.JWTManager.CreateIDToken(
		api.Config.Issuer,
		code.Subject,
		code.ClientID,
		time.Unix(code.AuthTime, 0),
		api.Config.TokenExpiresIn,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to generate access_token",
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"token_type":   "Bearer",
		"access_token": accessToken,
		"id_token":     idToken,
		"expires_in":   api.Config.TokenExpiresIn,
		"scope":        code.Scope,
	})
}
