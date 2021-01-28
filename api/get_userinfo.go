package api

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/config"
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

	conn, err := api.Connector.Connect()
	if err != nil {
		log.Print(err)
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Reason:      "server_error",
			Description: "failed to connecting LDAP server",
		})
		return
	}
	defer conn.Close()

	scope := ParseStringSet(token.Scope)
	attrs, err := conn.GetUserAttributes(token.Subject, api.Config.Scopes.AttributesFor(scope.List()))
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
			Description: "failed to get attributes",
		})
		return
	}

	maps := api.Config.Scopes.ClaimMapFor(scope.List())
	result := config.MappingClaims(attrs, maps)
	result["sub"] = token.Subject

	c.JSON(http.StatusOK, result)
}
