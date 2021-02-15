package errors

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

func SendHTML(c *gin.Context, e *Error) {
	c.HTML(e.StatusCode(), "error.tmpl", gin.H{
		"error": e,
	})
}

func SendRedirect(c *gin.Context, e *Error) {
	if e.RedirectURI == nil || e.RedirectURI.String() == "" || !e.RedirectURI.IsAbs() {
		SendHTML(c, e)
		return
	}

	resp := make(url.Values)
	if e.State != "" {
		resp.Set("state", e.State)
	}

	resp.Set("error", string(e.Reason))
	if e.Description != "" {
		resp.Set("error_description", e.Description)
	}

	if e.ResponseType != "code" && e.ResponseType != "" {
		e.RedirectURI.Fragment = resp.Encode()
	} else {
		e.RedirectURI.RawQuery = resp.Encode()
	}
	c.Redirect(http.StatusFound, e.RedirectURI.String())
}

func SendJSON(c *gin.Context, e *Error) {
	if e.Reason == InvalidToken {
		c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=\"invalid_token\",error_description=%#v", e.Description))
	}

	c.JSON(e.StatusCode(), e)
}
