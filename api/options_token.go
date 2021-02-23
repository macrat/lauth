package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/errors"
	"github.com/macrat/lauth/metrics"
)

func getOriginHeader(c *gin.Context) string {
	header := new(struct {
		Origin string `header:"Origin"`
	})
	c.BindHeader(&header)
	return header.Origin
}

func (api *LauthAPI) OptionsToken(c *gin.Context) {
	report := metrics.StartToken(c)
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	if getOriginHeader(c) != "" {
		e := &errors.Error{
			Reason:      errors.AccessDenied,
			Description: "Origin header was set. You can't use token endpoint via browser.",
		}
		report.SetError(e)
		c.JSON(http.StatusForbidden, e)
	}
}
