package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/ldap"
	"github.com/macrat/ldapin/metrics"
)

type GetUserInfoHeader struct {
	Authorization string `header:"Authorization"`
}

func (api *LdapinAPI) GetUserInfo(c *gin.Context) {
	report := metrics.StartUserinfo()
	defer report.Close()

	var header GetUserInfoHeader
	if err := c.ShouldBindHeader(&header); err != nil || !strings.HasPrefix(header.Authorization, "Bearer ") {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"bearer token is required\"")
		e := ErrorMessage{
			Err:         err,
			Reason:      "invalid_token",
			Description: "bearer token is required",
		}
		e.Report(report)
		e.JSON(c)
		return
	}

	rawToken := strings.TrimSpace(header.Authorization[len("Bearer "):])
	token, err := api.TokenManager.ParseAccessToken(rawToken)
	if err == nil {
		err = token.Validate(api.Config.Issuer)
	}
	if err != nil {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"token is invalid\"")
		e := ErrorMessage{
			Err:         err,
			Reason:      "invalid_token",
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
			Reason:      "invalid_token",
			Description: "user was not found or disabled",
		}
		e.Report(report)
		e.JSON(c)
	} else if err != nil {
		e := ErrorMessage{
			Reason:      "server_error",
			Description: "failed to get user info",
		}
		e.Report(report)
		e.JSON(c)
	} else {
		c.JSON(http.StatusOK, result)
	}
}
