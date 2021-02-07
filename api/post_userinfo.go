package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/metrics"
)

type PostUserInfoRequest struct {
	GetUserInfoRequest

	AccessToken string `form:"access_token" header:"-"`
}

func (req *PostUserInfoRequest) Bind(c *gin.Context) *ErrorMessage {
	if errMsg := (&req.GetUserInfoRequest).Bind(c); errMsg != nil {
		return errMsg
	}
	if err := c.ShouldBind(&req); err != nil {
		return &ErrorMessage{
			Err:         err,
			Reason:      InvalidToken,
			Description: "access token is required",
		}
	}
	return nil
}

func (req PostUserInfoRequest) GetToken() (string, *ErrorMessage) {
	token, err := req.GetUserInfoRequest.GetToken()
	if err == nil {
		return token, nil
	}

	if req.AccessToken == "" {
		return "", &ErrorMessage{
			Reason:      InvalidToken,
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
	if errMsg := (&req).Bind(c); errMsg != nil {
		c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\",error_description=\"access token is required\"")
		errMsg.Report(report)
		errMsg.JSON(c)
		return
	}

	rawToken, errMsg := req.GetToken()
	if errMsg != nil {
		c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\",error_description=\"access token is required\"")
		errMsg.Report(report)
		errMsg.JSON(c)
		return
	}

	result, errMsg := api.userinfoByToken(rawToken, report)
	if errMsg != nil {
		if errMsg.Reason == InvalidToken {
			c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\",error_description=\"token is invalid\"")
		}
		errMsg.Report(report)
		errMsg.JSON(c)
	} else {
		report.Success()
		c.JSON(http.StatusOK, result)
	}
}
