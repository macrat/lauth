package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/errors"
	"github.com/macrat/lauth/metrics"
)

type OptionsUserInfoRequest struct {
	Origin string `header:"Origin"`
}

func (api *LauthAPI) OptionsUserInfo(c *gin.Context) {
	report := metrics.StartUserinfo(c)
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	req := new(OptionsUserInfoRequest)
	if err := c.ShouldBindHeader(req); err == nil && req.Origin != "" {
		for clientID, settings := range api.Config.Clients {
			if settings.CORSOrigin.Match(req.Origin) {
				report.Set("client_id", clientID)
				c.Header("Access-Control-Allow-Origin", req.Origin)
				return
			}
		}
		e := &errors.Error{
			Reason:      errors.AccessDenied,
			Description: "Origin is not registered as a valid client",
		}
		report.SetError(e)
		c.JSON(http.StatusForbidden, e)
	}
}
