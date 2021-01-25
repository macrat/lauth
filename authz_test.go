package main_test

import (
	"net/http"
	"net/url"
)

var (
	authzEndpointCommonTests = []RedirectTest{
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
	}
)
