package api

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/errors"
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
	r.POST(endpoints.Userinfo, api.PostUserInfo)
	r.GET(endpoints.Jwks, api.GetCerts)
	r.GET(endpoints.Logout, api.Logout)
	r.POST(endpoints.Logout, api.Logout)
}

func (api *LauthAPI) SetErrorRoutes(r *gin.Engine) {
	r.NoRoute(func(c *gin.Context) {
		report := metrics.StartLogging(c)
		defer report.Close()

		endpoints := api.Config.EndpointPaths()

		methodNotAllowed := &errors.Error{
			Reason:      errors.MethodNotAllowed,
			Description: fmt.Sprintf("%s method is not supported in this page", c.Request.Method),
		}

		switch c.Request.URL.Path {
		case endpoints.Authz:
			report.SetError(methodNotAllowed)
			errors.SendHTML(c, methodNotAllowed)
		case endpoints.OpenIDConfiguration, endpoints.Token, endpoints.Userinfo, endpoints.Jwks:
			report.SetError(methodNotAllowed)
			c.JSON(http.StatusMethodNotAllowed, methodNotAllowed)
		default:
			notFound := &errors.Error{
				Reason:      errors.PageNotFound,
				Description: "requested page is not found",
			}
			report.SetError(notFound)
			errors.SendHTML(c, notFound)
		}
	})
}

func (api *LauthAPI) GetConfiguration(c *gin.Context) {
	report := metrics.StartLogging(c)
	defer report.Close()

	c.Header("Access-Control-Allow-Origin", "*")

	c.IndentedJSON(200, api.Config.OpenIDConfiguration())
}

func (api *LauthAPI) GetCerts(c *gin.Context) {
	report := metrics.StartLogging(c)
	defer report.Close()

	c.Header("Access-Control-Allow-Origin", "*")

	keys, err := api.TokenManager.JWKs((*url.URL)(api.Config.Issuer).Hostname())
	if err != nil {
		e := &errors.Error{
			Err:         err,
			Reason:      errors.ServerError,
			Description: "failed to get key informations",
		}
		report.SetError(e)
		errors.SendJSON(c, e)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"keys": keys,
	})
}
