package errors

import (
	"net/http"
	"net/url"
)

type Error struct {
	Err          error    `json:"-"`
	RedirectURI  *url.URL `json:"-"`
	ResponseType string   `json:"-"`
	State        string   `json:"state,omitempty"`
	Reason       Reason   `json:"error"`
	Description  string   `json:"error_description,omitempty"`
}

func (e *Error) Unwrap() error {
	return e.Err
}

func (e *Error) Error() string {
	msg := e.Reason.String()
	if e.Description != "" {
		msg += ": " + e.Description
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) StatusCode() int {
	switch e.Reason {
	case ServerError:
		return http.StatusInternalServerError
	case InvalidToken:
		return http.StatusForbidden
	case MethodNotAllowed:
		return http.StatusMethodNotAllowed
	case PageNotFound:
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}
