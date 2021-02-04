package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/ldap"
	"github.com/macrat/lauth/metrics"
	"github.com/macrat/lauth/token"
)

type LauthAPI struct {
	Connector    ldap.Connector
	Config       *config.Config
	TokenManager token.Manager
}

func (api *LauthAPI) SetRoutes(r gin.IRoutes) {
	endpoints := api.Config.EndpointPaths()

	r.GET(endpoints.OpenIDConfiguration, api.GetConfiguration)
	r.GET(endpoints.Authz, api.GetAuthz)
	r.POST(endpoints.Authz, api.PostAuthz)
	r.POST(endpoints.Token, api.PostToken)
	r.GET(endpoints.Userinfo, api.GetUserInfo)
	r.GET(endpoints.Jwks, api.GetCerts)
	r.GET(endpoints.Logout, api.Logout)
	r.POST(endpoints.Logout, api.Logout)
}

func (api *LauthAPI) SetErrorRoutes(r *gin.Engine) {
	r.NoRoute(func(c *gin.Context) {
		report := metrics.StartLogging(c)
		defer report.Close()

		endpoints := api.Config.EndpointPaths()

		methodNotAllowed := ErrorMessage{
			Reason:      "method_not_allowed",
			Description: fmt.Sprintf("%s method is not supported in this page", c.Request.Method),
		}

		switch c.Request.URL.Path {
		case endpoints.Authz:
			methodNotAllowed.Report(report)
			c.HTML(http.StatusMethodNotAllowed, "error.tmpl", gin.H{
				"error": methodNotAllowed,
			})
		case endpoints.OpenIDConfiguration, endpoints.Token, endpoints.Userinfo, endpoints.Jwks:
			methodNotAllowed.Report(report)
			c.JSON(http.StatusMethodNotAllowed, methodNotAllowed)
		default:
			notFound := ErrorMessage{
				Reason:      "page_not_found",
				Description: "requested page is not found",
			}
			notFound.Report(report)
			c.HTML(http.StatusNotFound, "error.tmpl", gin.H{
				"error": notFound,
			})
		}
	})
}

func (api *LauthAPI) GetConfiguration(c *gin.Context) {
	report := metrics.StartLogging(c)
	defer report.Close()

	c.IndentedJSON(200, api.Config.OpenIDConfiguration())
}

func (api *LauthAPI) GetCerts(c *gin.Context) {
	report := metrics.StartLogging(c)
	defer report.Close()

	keys, err := api.TokenManager.JWKs()
	if err != nil {
		e := ErrorMessage{
			Err:         err,
			Reason:      "server_error",
			Description: "failed to get key informations",
		}
		e.Report(report)
		e.JSON(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"keys": keys,
	})
}
