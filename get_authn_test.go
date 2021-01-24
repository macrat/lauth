package main_test

import (
	"net/http"
	"net/url"
	"testing"
)

func TestGetAuthn(t *testing.T) {
	env := NewAPITestEnvironment(t)

	env.RedirectTest(t, "GET", "/authn", authnEndpointCommonTests)

	env.RedirectTest(t, "GET", "/authn", []RedirectTest{
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"code"},
			},
			Code: http.StatusOK,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"code token"},
			},
			Code: http.StatusOK,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"code"},
				"prompt":        {"none"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"login_required"},
				"error_description": {"prompt=none is not supported"},
			},
			Fragment: url.Values{},
		},
	})
}
