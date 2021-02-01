package api

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/metrics"
)

var (
	AccessDenied            ErrorReason = "access_denied"
	InvalidClient           ErrorReason = "invalid_client"
	InvalidGrant            ErrorReason = "invalid_grant"
	InvalidRequest          ErrorReason = "invalid_request"
	InvalidScope            ErrorReason = "invalid_scope"
	InvalidToken            ErrorReason = "invalid_token"
	RequestNotSupported     ErrorReason = "request_not_supported"
	RequestURINotSupported  ErrorReason = "request_uri_not_supported"
	ServerError             ErrorReason = "server_error"
	TemporarilyUnavailable  ErrorReason = "temporarily_unavailable"
	UnauthorizedClient      ErrorReason = "unauthorized_client"
	UnsupportedGrantType    ErrorReason = "unsupported_grant_type"
	UnsupportedResponseType ErrorReason = "unsupported_response_type"
)

type ErrorReason string

func (e ErrorReason) String() string {
	return string(e)
}

type ErrorMessage struct {
	Err          error       `json:"-"`
	RedirectURI  *url.URL    `json:"-"`
	ResponseType string      `json:"-"`
	State        string      `json:"state,omitempty"`
	Reason       ErrorReason `json:"error"`
	Description  string      `json:"error_description,omitempty"`
	ErrorURI     string      `json:"error_uri,omitempty"`
}

func (msg ErrorMessage) Unwrap() error {
	return msg.Err
}

func (msg ErrorMessage) Error() string {
	if msg.State == "" {
		return fmt.Sprintf("%s: %s", msg.Reason, msg.Description)
	} else {
		return fmt.Sprintf("%s(%s): %s", msg.Reason, msg.State, msg.Description)
	}
}

func (msg ErrorMessage) Redirect(c *gin.Context) {
	if msg.RedirectURI == nil || msg.RedirectURI.String() == "" || !msg.RedirectURI.IsAbs() {
		c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{
			"error": msg,
		})
		return
	}

	resp := make(url.Values)
	if msg.State != "" {
		resp.Set("state", msg.State)
	}

	resp.Set("error", string(msg.Reason))
	if msg.Description != "" {
		resp.Set("error_description", msg.Description)
	}

	if msg.ResponseType != "code" && msg.ResponseType != "" {
		msg.RedirectURI.Fragment = resp.Encode()
	} else {
		msg.RedirectURI.RawQuery = resp.Encode()
	}
	c.Redirect(http.StatusFound, msg.RedirectURI.String())
}

func (msg ErrorMessage) JSON(c *gin.Context) {
	switch msg.Reason {
	case "server_error":
		c.JSON(http.StatusInternalServerError, msg)
	case "invalid_token":
		c.JSON(http.StatusForbidden, msg)
	default:
		c.JSON(http.StatusBadRequest, msg)
	}
}

func (msg ErrorMessage) Report(r metrics.ErrorReporter) {
	r.SetError(msg.Err, string(msg.Reason), msg.Description)
}
