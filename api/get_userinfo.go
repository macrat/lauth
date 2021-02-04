package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/ldap"
	"github.com/macrat/lauth/metrics"
)

type GetUserInfoHeader struct {
	Authorization string `header:"Authorization"`
}

func (api *LauthAPI) GetUserInfo(c *gin.Context) {
	report := metrics.StartUserinfo(c)
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var header GetUserInfoHeader
	if err := c.ShouldBindHeader(&header); err != nil || !strings.HasPrefix(header.Authorization, "Bearer ") {
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

	rawToken := strings.TrimSpace(header.Authorization[len("Bearer "):])
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
	result, err := api.userinfo(token.Subject, scope)
	if err == ldap.UserNotFoundError {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"token is invalid\"")
		e := ErrorMessage{
			Err:         err,
			Reason:      InvalidToken,
			Description: "user was not found or disabled",
		}
		e.Report(report)
		e.JSON(c)
	} else if err != nil {
		e := ErrorMessage{
			Reason:      ServerError,
			Description: "failed to get user info",
		}
		e.Report(report)
		e.JSON(c)
	} else {
		report.Success()
		c.JSON(http.StatusOK, result)
	}
}
