package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/metrics"
)

type GetUserInfoRequest struct {
	Authorization string `header:"Authorization"`
}

func (req GetUserInfoRequest) GetToken() (string, *ErrorMessage) {
	if !strings.HasPrefix(req.Authorization, "Bearer ") {
		return "", &ErrorMessage{
			Reason:      InvalidToken,
			Description: "bearer token is required",
		}
	}

	return strings.TrimSpace(req.Authorization[len("Bearer "):]), nil
}

func (api *LauthAPI) GetUserInfo(c *gin.Context) {
	report := metrics.StartUserinfo(c)
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var req GetUserInfoRequest
	if err := c.ShouldBindHeader(&req); err != nil {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"bearer token is required\"")
		e := ErrorMessage{
			Err:         err,
			Reason:      InvalidToken,
			Description: "bearer token is required",
		}
		e.Report(report)
		e.JSON(c)
		return
	}

	rawToken, errMsg := req.GetToken()
	if errMsg != nil {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"bearer token is required\"")
		errMsg.Report(report)
		errMsg.JSON(c)
		return
	}

	token, err := api.TokenManager.ParseAccessToken(rawToken)
	if err == nil {
		report.Set("client_id", token.Audience)
		report.Set("username", token.Subject)
		err = token.Validate(api.Config.Issuer)
	}

	if err != nil {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"token is invalid\"")
		e := ErrorMessage{
			Err:         err,
			Reason:      InvalidToken,
			Description: "token is invalid",
		}
		e.Report(report)
		e.JSON(c)
		return
	}

	scope := ParseStringSet(token.Scope)
	result, errMsg := api.userinfo(token.Subject, scope)
	if errMsg != nil {
		if errMsg.Reason == InvalidToken {
			c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"token is invalid\"")
		}
		errMsg.Report(report)
		errMsg.JSON(c)
	} else {
		report.Success()
		c.JSON(http.StatusOK, result)
	}
}
