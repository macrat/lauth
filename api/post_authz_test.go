package api_test

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/macrat/ldapin/testutil"
)

func TestPostAuthz(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	env.RedirectTest(t, "GET", "/authz", authzEndpointCommonTests)

	env.RedirectTest(t, "POST", "/authz", []testutil.RedirectTest{
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"code"},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"code"},
				"username":      {"macrat"},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"code"},
				"password":      {"foobar"},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"code"},
				"username":      {"macrat"},
				"password":      {"invalid"},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"code"},
				"username":      {"macrat"},
				"password":      {"foobar"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			CheckParams: func(t *testing.T, query, fragment url.Values) {
				if !reflect.DeepEqual(fragment, url.Values{}) {
					t.Errorf("expected fragment is not set but set %#v", fragment.Encode())
				}
				if query.Get("code") == "" {
					t.Errorf("expected returns code but not set")
				} else if code, err := env.API.TokenManager.ParseCode(query.Get("code")); err != nil {
					t.Errorf("failed to parse code: %s", err)
				} else if err := code.Validate(env.API.Config.Issuer); err != nil {
					t.Errorf("failed to validate code: %s", err)
				}
				if query.Get("access_token") != "" {
					t.Errorf("expected access_token is not set but set %#v", query.Get("access_token"))
				}
				if query.Get("id_token") != "" {
					t.Errorf("expected id_token is not set but set %#v", query.Get("id_token"))
				}
			},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"token"},
				"username":      {"macrat"},
				"password":      {"foobar"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			CheckParams: func(t *testing.T, query, fragment url.Values) {
				if !reflect.DeepEqual(query, url.Values{}) {
					t.Errorf("expected query is not set but set %#v", query.Encode())
				}
				if fragment.Get("access_token") == "" {
					t.Errorf("expected returns access_token but not set")
				} else if code, err := env.API.TokenManager.ParseAccessToken(fragment.Get("access_token")); err != nil {
					t.Errorf("failed to parse access_token: %s", err)
				} else if err := code.Validate(env.API.Config.Issuer); err != nil {
					t.Errorf("failed to validate access_token: %s", err)
				}
				if fragment.Get("code") != "" {
					t.Errorf("expected code is not set but set %#v", fragment.Get("code"))
				}
				if fragment.Get("id_token") != "" {
					t.Errorf("expected id_token is not set but set %#v", fragment.Get("id_token"))
				}
				if fragment.Get("token_type") != "Bearer" {
					t.Errorf("expected token_type is \"Bearer\" but got %#v", fragment.Get("token_type"))
				}
				if fragment.Get("expires_in") != "3600" {
					t.Errorf("expected token_type is \"3600\" but got %#v", fragment.Get("expires_in"))
				}
				if fragment.Get("state") != "" {
					t.Errorf("expected state is not set but got %#v", fragment.Get("state"))
				}
			},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"id_token"},
				"state":         {"this-is-state"},
				"username":      {"macrat"},
				"password":      {"foobar"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			CheckParams: func(t *testing.T, query, fragment url.Values) {
				if !reflect.DeepEqual(query, url.Values{}) {
					t.Errorf("expected query is not set but set %#v", query.Encode())
				}
				if fragment.Get("id_token") == "" {
					t.Errorf("expected returns id_token but not set")
				} else if code, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse access_token: %s", err)
				} else if err := code.Validate(env.API.Config.Issuer, "test_client"); err != nil {
					t.Errorf("failed to validate access_token: %s", err)
				}
				if fragment.Get("code") != "" {
					t.Errorf("expected code is not set but set %#v", fragment.Get("code"))
				}
				if fragment.Get("access_token") != "" {
					t.Errorf("expected access_token is not set but set %#v", fragment.Get("access_token"))
				}
				if fragment.Get("expires_in") != "3600" {
					t.Errorf("expected token_type is \"3600\" but got %#v", fragment.Get("expires_in"))
				}
				if fragment.Get("state") != "this-is-state" {
					t.Errorf("expected state is \"this-is-state\" but got %#v", fragment.Get("state"))
				}
			},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"token id_token"},
				"username":      {"macrat"},
				"password":      {"foobar"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			CheckParams: func(t *testing.T, query, fragment url.Values) {
				if !reflect.DeepEqual(query, url.Values{}) {
					t.Errorf("expected query is not set but set %#v", query.Encode())
				}
				if fragment.Get("access_token") == "" {
					t.Errorf("expected returns access_token but not set")
				}
				if fragment.Get("id_token") == "" {
					t.Errorf("expected returns id_token but not set")
				}
				if fragment.Get("code") != "" {
					t.Errorf("expected code is not set but set %#v", fragment.Get("code"))
				}
			},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://localhost:3000"},
				"client_id":     {"test_client"},
				"response_type": {"code id_token"},
				"username":      {"macrat"},
				"password":      {"foobar"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			CheckParams: func(t *testing.T, query, fragment url.Values) {
				if !reflect.DeepEqual(query, url.Values{}) {
					t.Errorf("expected query is not set but set %#v", query.Encode())
				}
				if fragment.Get("code") == "" {
					t.Errorf("expected returns code but not set")
				}
				if fragment.Get("id_token") == "" {
					t.Errorf("expected returns id_token but not set")
				}
				if fragment.Get("access_token") != "" {
					t.Errorf("expected access_token is not set but set %#v", fragment.Get("access_token"))
				}
			},
		},
	})
}
