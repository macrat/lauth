package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type LdapinAPI struct {
	Connector  LDAPConnector
	Config     *LdapinConfig
	JWTManager JWTManager
}

func (api *LdapinAPI) SetRoutes(r gin.IRoutes) {
	endpoints := api.Config.EndpointPaths()

	r.GET(endpoints.OpenIDConfiguration, api.GetConfiguration)
	r.GET(endpoints.Authz, api.GetAuthz)
	r.POST(endpoints.Authz, api.PostAuthz)
	r.POST(endpoints.Token, api.PostToken)
	r.GET(endpoints.Userinfo, api.GetUserInfo)
	r.GET(endpoints.Jwks, api.GetCerts)
}

func (api *LdapinAPI) GetConfiguration(c *gin.Context) {
	c.IndentedJSON(200, api.Config.OpenIDConfiguration())
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

	c.JSON(http.StatusOK, gin.H{
		"keys": keys,
	})
}
