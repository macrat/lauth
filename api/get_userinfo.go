package api

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/errors"
	"github.com/macrat/lauth/metrics"
)

type GetUserInfoRequest struct {
	Authorization string `form:"-" header:"Authorization"`
	Origin        string `form:"-" header:"Origin"`
}

func (req *GetUserInfoRequest) Bind(c *gin.Context) *errors.Error {
	if err := c.ShouldBindHeader(req); err != nil {
		return &errors.Error{
			Err:         err,
			Reason:      errors.InvalidToken,
			Description: "failed to parse request headers",
		}
	}

	return nil
}

func (req GetUserInfoRequest) GetToken() (string, *errors.Error) {
	if !strings.HasPrefix(req.Authorization, "Bearer ") {
		return "", &errors.Error{
			Reason:      errors.InvalidToken,
			Description: "access token is required",
		}
	}

	return strings.TrimSpace(req.Authorization[len("Bearer "):]), nil
}

func (api *LauthAPI) GetUserInfo(c *gin.Context) {
	report := metrics.StartUserinfo(c)
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var req GetUserInfoRequest
	if err := (&req).Bind(c); err != nil {
		report.SetError(err)
		errors.SendJSON(c, err)
		return
	}

	rawToken, err := req.GetToken()
	if err != nil {
		report.SetError(err)
		errors.SendJSON(c, err)
		return
	}

	api.sendUserInfo(c, report, req.Origin, rawToken)
}
