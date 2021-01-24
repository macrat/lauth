package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type PostAuthnRequest struct {
	GetAuthnRequest

	User     string `form:"username" json:"username" xml:"username"`
	Password string `form:"password" json:"password" xml:"password"`
}

func (req *PostAuthnRequest) Bind(c *gin.Context) *ErrorMessage {
	err := c.ShouldBind(req)
	if err != nil {
		return &ErrorMessage{
			Err:         err,
			Reason:      "invalid_request",
			Description: "failed to parse request",
		}
	}
	return nil
}

func (req *PostAuthnRequest) BindAndValidate(c *gin.Context) *ErrorMessage {
	if err := req.Bind(c); err != nil {
		return err
	}
	return req.Validate()
}

func (api *LdapinAPI) PostAuthn(c *gin.Context) {
	var req PostAuthnRequest
	if err := (&req).BindAndValidate(c); err != nil {
		err.Redirect(c)
		return
	}
	scope := ParseStringSet(req.Scope)
	scope.Add("openid")
	req.Scope = scope.String()

	if req.User == "" || req.Password == "" {
		c.HTML(http.StatusForbidden, "login.tmpl", gin.H{
			"config":           api.Config,
			"request":          req.GetAuthnRequest,
			"initial_username": req.User,
			"error":            "missing_username_or_password",
		})
		return
	}

	conn, err := api.Connector.Connect()
	if err != nil {
		log.Print(err)
		req.makeError(err, "server_error", "failed to connecting LDAP server").Redirect(c)
		return
	}
	defer conn.Close()

	if err := conn.LoginTest(req.User, req.Password); err != nil {
		c.HTML(http.StatusForbidden, "login.tmpl", gin.H{
			"config":           api.Config,
			"request":          req.GetAuthnRequest,
			"initial_username": req.User,
			"error":            "invalid_username_or_password",
		})
		return
	}

	resp, errMsg := MakeAuthnTokens(api.JWTManager, api.Config, req.GetAuthnRequest, req.User)
	if errMsg != nil {
		errMsg.Redirect(c)
	}

	c.Redirect(http.StatusFound, resp.String())
}
