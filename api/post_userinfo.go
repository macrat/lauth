package api

import (
	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/errors"
	"github.com/macrat/lauth/metrics"
)

type PostUserInfoRequest struct {
	GetUserInfoRequest

	AccessToken string `form:"access_token" header:"-"`
}

func (req *PostUserInfoRequest) Bind(c *gin.Context) *errors.Error {
	if e := (&req.GetUserInfoRequest).Bind(c); e != nil {
		return e
	}
	if err := c.ShouldBind(&req); err != nil {
		return &errors.Error{
			Err:         err,
			Reason:      errors.InvalidToken,
			Description: "failed to parse request body",
		}
	}
	return nil
}

func (req PostUserInfoRequest) GetToken() (string, *errors.Error) {
	token, err := req.GetUserInfoRequest.GetToken()
	if err == nil {
		return token, nil
	}

	if req.AccessToken == "" {
		return "", &errors.Error{
			Reason:      errors.InvalidToken,
			Description: "access token is required",
		}
	}

	return req.AccessToken, nil
}

func (api *LauthAPI) PostUserInfo(c *gin.Context) {
	report := metrics.StartUserinfo(c)
	defer report.Close()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var req PostUserInfoRequest
	if e := (&req).Bind(c); e != nil {
		report.SetError(e)
		errors.SendJSON(c, e)
		return
	}

	rawToken, e := req.GetToken()
	if e != nil {
		report.SetError(e)
		errors.SendJSON(c, e)
		return
	}

	api.sendUserInfo(c, report, req.Origin, rawToken)
}
