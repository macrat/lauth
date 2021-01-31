package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/config"
	"github.com/macrat/ldapin/ldap"
	"github.com/macrat/ldapin/token"
)

type LdapinAPI struct {
	Connector    ldap.Connector
	Config       *config.Config
	TokenManager token.Manager
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

func (api *LdapinAPI) SetErrorRoutes(r *gin.Engine) {
	r.NoRoute(func(c *gin.Context) {
		endpoints := api.Config.EndpointPaths()

		methodNotAllowed := ErrorMessage{
			Reason:      "method_not_allowed",
			Description: fmt.Sprintf("%s method is not supported in this page", c.Request.Method),
		}

		switch c.Request.URL.Path {
		case endpoints.Authz:
			c.HTML(http.StatusMethodNotAllowed, "error.tmpl", gin.H{
				"error": methodNotAllowed,
			})
		case endpoints.OpenIDConfiguration, endpoints.Token, endpoints.Userinfo, endpoints.Jwks:
			c.JSON(http.StatusMethodNotAllowed, methodNotAllowed)
		default:
			c.HTML(http.StatusNotFound, "error.tmpl", gin.H{
				"error": ErrorMessage{
					Reason:      "page_not_found",
					Description: "requested page is not found",
				},
			})
		}
	})
}

func (api *LdapinAPI) GetConfiguration(c *gin.Context) {
	c.IndentedJSON(200, api.Config.OpenIDConfiguration())
}

func (api *LdapinAPI) GetCerts(c *gin.Context) {
	keys, err := api.TokenManager.JWKs()
	if err != nil {
		ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to get key informations",
		}.JSON(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"keys": keys,
	})
}
