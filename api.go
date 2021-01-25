package main

import (
	"net/http"
	"path"

	"github.com/gin-gonic/gin"
)

type LdapinAPI struct {
	Connector  LDAPConnector
	Config     *LdapinConfig
	JWTManager JWTManager
}

func (api *LdapinAPI) SetRoutes(r gin.IRoutes) {
	r.GET(path.Join(api.Config.Endpoints.BasePath, "/.well-known/openid-configuration"), api.GetConfiguration)
	r.GET(path.Join(api.Config.Endpoints.BasePath, api.Config.Endpoints.Authn), api.GetAuthn)
	r.POST(path.Join(api.Config.Endpoints.BasePath, api.Config.Endpoints.Authn), api.PostAuthn)
	r.POST(path.Join(api.Config.Endpoints.BasePath, api.Config.Endpoints.Token), api.PostToken)
	r.GET(path.Join(api.Config.Endpoints.BasePath, api.Config.Endpoints.Userinfo), api.GetUserInfo)
	r.GET(path.Join(api.Config.Endpoints.BasePath, api.Config.Endpoints.Jwks), api.GetCerts)
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

	c.Header("Content-Type", "application/jwk-set+json")
	c.JSON(http.StatusOK, gin.H{
		"keys": keys,
	})
}
