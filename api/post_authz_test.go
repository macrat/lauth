package api_test

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/macrat/ldapin/testutil"
	"github.com/macrat/ldapin/token"
)

func TestPostAuthz(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	env.RedirectTest(t, "GET", "/authz", authzEndpointCommonTests)

	session, err := env.API.MakeLoginSession("::1", "some_client_id")
	if err != nil {
		t.Fatalf("faield to make login session: %s", err)
	}

	anotherBrowserSession, err := env.API.MakeLoginSession("10.2.3.4", "some_client_id")
	if err != nil {
		t.Fatalf("faield to make login session: %s", err)
	}

	anotherClientSession, err := env.API.MakeLoginSession("::1", "another_client_id")
	if err != nil {
		t.Fatalf("faield to make login session: %s", err)
	}

	env.RedirectTest(t, "POST", "/authz", []testutil.RedirectTest{
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"session":       {session},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"username":      {"macrat"},
				"session":       {session},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"password":      {"foobar"},
				"session":       {session},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"username":      {"macrat"},
				"password":      {"invalid"},
				"session":       {session},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"username":      {"macrat"},
				"password":      {"foobar"},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"username":      {"macrat"},
				"password":      {"foobar"},
				"session":       {anotherBrowserSession},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"username":      {"macrat"},
				"password":      {"foobar"},
				"session":       {anotherClientSession},
			},
			Code: http.StatusForbidden,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"username":      {"macrat"},
				"password":      {"foobar"},
				"session":       {session},
			},
			AllowImplicit: false,
			Code:          http.StatusFound,
			HasLocation:   true,
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
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"token"},
				"username":      {"macrat"},
				"password":      {"foobar"},
				"session":       {session},
			},
			AllowImplicit: true,
			Code:          http.StatusFound,
			HasLocation:   true,
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
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"id_token"},
				"state":         {"this-is-state"},
				"username":      {"macrat"},
				"password":      {"foobar"},
				"session":       {session},
			},
			AllowImplicit: true,
			Code:          http.StatusFound,
			HasLocation:   true,
			CheckParams: func(t *testing.T, query, fragment url.Values) {
				if !reflect.DeepEqual(query, url.Values{}) {
					t.Errorf("expected query is not set but set %#v", query.Encode())
				}
				if fragment.Get("id_token") == "" {
					t.Errorf("expected returns id_token but not set")
				} else if code, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse access_token: %s", err)
				} else if err := code.Validate(env.API.Config.Issuer, "some_client_id"); err != nil {
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

				if idToken, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse id_token: %s", err)
				} else if len(idToken.ExtraClaims) != 0 {
					t.Errorf("create id_token without scopes but got some extra claims: %#v", idToken.ExtraClaims)
				}
			},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"id_token"},
				"scope":         {"profile"},
				"state":         {"this-is-state"},
				"username":      {"macrat"},
				"password":      {"foobar"},
				"session":       {session},
			},
			AllowImplicit: true,
			Code:          http.StatusFound,
			HasLocation:   true,
			CheckParams: func(t *testing.T, query, fragment url.Values) {
				if !reflect.DeepEqual(query, url.Values{}) {
					t.Errorf("expected query is not set but set %#v", query.Encode())
				}
				if fragment.Get("id_token") == "" {
					t.Errorf("expected returns id_token but not set")
				} else if code, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse access_token: %s", err)
				} else if err := code.Validate(env.API.Config.Issuer, "some_client_id"); err != nil {
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

				expectedClaims := token.ExtraClaims{
					"name":        "SHIDA Yuuma",
					"given_name":  "yuuma",
					"family_name": "shida",
				}

				if idToken, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse id_token: %s", err)
				} else if !reflect.DeepEqual(idToken.ExtraClaims, expectedClaims) {
					t.Errorf("unexpected extra claims: %#v", idToken.ExtraClaims)
				}
			},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"token id_token"},
				"username":      {"macrat"},
				"password":      {"foobar"},
				"session":       {session},
			},
			AllowImplicit: true,
			Code:          http.StatusFound,
			HasLocation:   true,
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

				if idToken, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse id_token: %s", err)
				} else if idToken.AccessTokenHash != token.TokenHash(fragment.Get("access_token")) {
					t.Errorf("at_hash is not match\nfrom id_token: %s\ncalculated: %s", idToken.AccessTokenHash, token.TokenHash(fragment.Get("access_token")))
				}
			},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code id_token"},
				"username":      {"macrat"},
				"password":      {"foobar"},
				"session":       {session},
			},
			AllowImplicit: true,
			Code:          http.StatusFound,
			HasLocation:   true,
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

				if idToken, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse id_token: %s", err)
				} else if idToken.CodeHash != token.TokenHash(fragment.Get("code")) {
					t.Errorf("c_hash is not match\nfrom id_token: %s\ncalculated: %s", idToken.CodeHash, token.TokenHash(fragment.Get("code")))
				}
			},
		},
	})
}
