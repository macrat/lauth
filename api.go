package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type LdapinAPI struct {
	Connector  LDAPConnector
	Config     LdapinConfig
	JWTManager JWTManager
}

func (api *LdapinAPI) GetConfiguration(c *gin.Context) {
	c.JSON(200, api.Config.OpenIDConfiguration())
}

func (api *LdapinAPI) GetCerts(c *gin.Context) {
	keys, err := api.JWTManager.JWKs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to get key informations",
		})
		return
	}

	c.JSON(http.StatusOK, keys)
}
