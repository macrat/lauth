package main_test

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestGetAuthn(t *testing.T) {
	env := NewAPITestEnvironment(t)

	tests := []struct {
		Request     url.Values
		Code        int
		HasLocation bool
		Query       url.Values
		Fragment    url.Values
	}{
		{
			Request:     url.Values{},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"response_type": {"code"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"client_id is required"},
			},
			Fragment: url.Values{},
		},
		{
			Request: url.Values{
				"redirect_uri": {"http://localhost:3000"},
				"client_id":    {"test_client"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"unsupported_response_type"},
				"error_description": {"response_type is required"},
			},
			Fragment: url.Values{},
		},
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
				"response_type": {"code hogefuga"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query:       url.Values{},
			Fragment: url.Values{
				"error":             {"unsupported_response_type"},
				"error_description": {"response_type \"hogefuga\" is not supported"},
			},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"/invalid/relative/url"},
				"client_id":     {"test_client"},
				"response_type": {"code"},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
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
	}

	for _, tt := range tests {
		resp := env.Get("/authn", tt.Request)

		if resp.Code != tt.Code {
			t.Errorf("%s: expected status code %d but got %d", tt.Request.Encode(), tt.Code, resp.Code)
		}

		location := resp.Header().Get("Location")
		if !tt.HasLocation {
			if location != "" {
				t.Errorf("%s: expected has no Location but got %#v", tt.Request.Encode(), location)
			}
		} else {
			if location == "" {
				t.Errorf("%s: expected Location header but not set", tt.Request.Encode())
				continue
			}

			loc, err := url.Parse(location)
			if err != nil {
				t.Errorf("%s: failed to parse Location header: %s", tt.Request.Encode(), err)
				continue
			}

			if !reflect.DeepEqual(loc.Query(), tt.Query) {
				t.Errorf("%s: redirect with unexpected query: %#v", tt.Request.Encode(), location)
			}

			fragment, err := url.ParseQuery(loc.Fragment)
			if err != nil {
				t.Errorf("%s: failed to parse Location fragment: %s", tt.Request.Encode(), err)
			}
			if !reflect.DeepEqual(fragment, tt.Fragment) {
				t.Errorf("%s: redirect with unexpected fragment: %#v", tt.Request.Encode(), location)
			}
		}
	}
}
