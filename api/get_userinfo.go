package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/ldap"
)

type GetUserInfoHeader struct {
	Authorization string `header:"Authorization"`
}

func (api *LdapinAPI) GetUserInfo(c *gin.Context) {
	var header GetUserInfoHeader
	if err := c.ShouldBindHeader(&header); err != nil || !strings.HasPrefix(header.Authorization, "Bearer ") {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"bearer token is required\"")
		c.JSON(http.StatusForbidden, ErrorMessage{
			Reason:      "invalid_token",
			Description: "bearer token is required",
		})
		return
	}

	rawToken := strings.TrimSpace(header.Authorization[len("Bearer "):])
	token, err := api.TokenManager.ParseAccessToken(rawToken)
	if err == nil {
		err = token.Validate(api.Config.Issuer)
	}
	if err != nil {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"token is invalid\"")
		c.JSON(http.StatusForbidden, ErrorMessage{
			Err:         err,
			Reason:      "invalid_token",
			Description: "token is invalid",
		})
		return
	}

	scope := ParseStringSet(token.Scope)
	result, err := api.userinfo(token.Subject, scope)
	if err == ldap.UserNotFoundError {
		c.Header("WWW-Authenticate", "error=\"invalid_token\",error_description=\"token is invalid\"")
		c.JSON(http.StatusForbidden, ErrorMessage{
			Err:         err,
			Reason:      "invalid_token",
			Description: "user was not found or disabled",
		})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Reason:      "server_error",
			Description: "failed to get user info",
		})
		return
	}

	c.JSON(http.StatusOK, result)
}
