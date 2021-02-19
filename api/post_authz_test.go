package api_test

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
	"github.com/macrat/lauth/token"
)

func TestPostAuthz(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	env.RedirectTest(t, "POST", "/authz", authzEndpointCommonTests(t, env.API.Config))

	expiresAt := time.Now().Add(10 * time.Minute)

	someRequest, err := env.API.TokenManager.CreateRequestObject(
		env.API.Config.Issuer,
		"::1",
		token.RequestObjectClaims{
			ClientID:     "some_client_id",
			RedirectURI:  "http://some-client.example.com/callback",
			ResponseType: "code",
		},
		expiresAt,
	)
	if err != nil {
		t.Fatalf("faield to make request: %s", err)
	}

	implicitRequest := func(responseType, scope, state string) string {
		request, err := env.API.TokenManager.CreateRequestObject(
			env.API.Config.Issuer,
			"::1",
			token.RequestObjectClaims{
				ClientID:     "implicit_client_id",
				RedirectURI:  "http://implicit-client.example.com/callback",
				ResponseType: responseType,
				Scope:        scope,
				State:        state,
			},
			expiresAt,
		)
		if err != nil {
			t.Fatalf("faield to make request: %s", err)
		}
		return request
	}

	anotherBrowserRequest, err := env.API.TokenManager.CreateRequestObject(
		env.API.Config.Issuer,
		"10.2.3.4",
		token.RequestObjectClaims{
			ClientID:     "some_client_id",
			RedirectURI:  "http://some-client.example.com/callback",
			ResponseType: "code",
		},
		expiresAt,
	)
	if err != nil {
		t.Fatalf("faield to make request: %s", err)
	}

	anotherIssuerRequest, err := env.API.TokenManager.CreateRequestObject(
		&config.URL{Scheme: "https", Host: "invalid-issuer.example.com"},
		"::1",
		token.RequestObjectClaims{
			ClientID:     "some_client_id",
			RedirectURI:  "http://some-client.example.com/callback",
			ResponseType: "code",
		},
		expiresAt,
	)
	if err != nil {
		t.Fatalf("faield to make request: %s", err)
	}

	anotherSignKeyRequest := testutil.SomeClientRequestObject(t, map[string]interface{}{
		"iss":           env.API.Config.Issuer.String(),
		"sub":           "::1",
		"aud":           env.API.Config.Issuer.String(),
		"client_id":     "some_client_id",
		"redirect_uri":  "http://some-client.example.com/callback",
		"response_type": "code",
	})

	expiredRequest, err := env.API.TokenManager.CreateRequestObject(
		env.API.Config.Issuer,
		"::1",
		token.RequestObjectClaims{
			ClientID:     "some_client_id",
			RedirectURI:  "http://some-client.example.com/callback",
			ResponseType: "code",
		},
		time.Now().Add(-10*time.Minute),
	)
	if err != nil {
		t.Fatalf("faield to make request: %s", err)
	}

	env.RedirectTest(t, "POST", "/authz", []testutil.RedirectTest{
		{
			Name: "missing username and password",
			Request: url.Values{
				"request": {someRequest},
			},
			Code: http.StatusForbidden,
		},
		{
			Name: "missing password",
			Request: url.Values{
				"request":  {someRequest},
				"username": {"macrat"},
			},
			Code: http.StatusForbidden,
		},
		{
			Name: "missing username",
			Request: url.Values{
				"request":  {someRequest},
				"password": {"foobar"},
			},
			Code: http.StatusForbidden,
		},
		{
			Name: "invalid password",
			Request: url.Values{
				"request":  {someRequest},
				"username": {"macrat"},
				"password": {"invalid"},
			},
			Code: http.StatusForbidden,
		},
		{
			Name: "missing request object",
			Request: url.Values{
				"username": {"macrat"},
				"password": {"foobar"},
			},
			Code: http.StatusBadRequest,
		},
		{
			Name: "request object of another issuer",
			Request: url.Values{
				"request":  {anotherIssuerRequest},
				"username": {"macrat"},
				"password": {"foobar"},
			},
			Code: http.StatusBadRequest,
		},
		{
			Name: "request object of client",
			Request: url.Values{
				"request":  {anotherSignKeyRequest},
				"username": {"macrat"},
				"password": {"foobar"},
			},
			Code: http.StatusBadRequest,
		},
		{
			Name: "another browser session",
			Request: url.Values{
				"request":  {anotherBrowserRequest},
				"username": {"macrat"},
				"password": {"foobar"},
			},
			Code: http.StatusBadRequest,
		},
		{
			Name: "request object has expired",
			Request: url.Values{
				"request":  {expiredRequest},
				"username": {"macrat"},
				"password": {"foobar"},
			},
			Code:         http.StatusBadRequest,
			BodyIncludes: []string{"access_denied", "login session is timed out"},
		},
		{
			Name: "success / code",
			Request: url.Values{
				"request":  {someRequest},
				"username": {"macrat"},
				"password": {"foobar"},
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
			Name: "success / token",
			Request: url.Values{
				"request":  {implicitRequest("token", "", "")},
				"username": {"macrat"},
				"password": {"foobar"},
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
			Name: "success / id_token",
			Request: url.Values{
				"request":  {implicitRequest("id_token", "openid", "this is state")},
				"username": {"macrat"},
				"password": {"foobar"},
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
				} else if err := code.Validate(env.API.Config.Issuer, "implicit_client_id"); err != nil {
					t.Errorf("failed to validate access_token: %s", err)
				}
				if fragment.Get("code") != "" {
					t.Errorf("expected code is not set but set %#v", fragment.Get("code"))
				}
				if fragment.Get("access_token") != "" {
					t.Errorf("expected access_token is not set but set %#v", fragment.Get("access_token"))
				}
				if fragment.Get("expires_in") != "3600" {
					t.Errorf("expected expires_in is \"3600\" but got %#v", fragment.Get("expires_in"))
				}
				if fragment.Get("state") != "this is state" {
					t.Errorf("expected state is \"this is state\" but got %#v", fragment.Get("state"))
				}

				if idToken, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse id_token: %s", err)
				} else if len(idToken.ExtraClaims) != 0 {
					t.Errorf("create id_token without scopes but got some extra claims: %#v", idToken.ExtraClaims)
				}
			},
		},
		{
			Name: "success / id_token with profile scope",
			Request: url.Values{
				"request":  {implicitRequest("id_token", "openid profile", "hello world")},
				"username": {"macrat"},
				"password": {"foobar"},
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
				} else if err := code.Validate(env.API.Config.Issuer, "implicit_client_id"); err != nil {
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
				if fragment.Get("state") != "hello world" {
					t.Errorf("expected state is \"hello world\" but got %#v", fragment.Get("state"))
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
			Name: "success / token id_token",
			Request: url.Values{
				"request":  {implicitRequest("token id_token", "openid", "")},
				"username": {"macrat"},
				"password": {"foobar"},
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

				if idToken, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse id_token: %s", err)
				} else if idToken.AccessTokenHash != token.TokenHash(fragment.Get("access_token")) {
					t.Errorf("at_hash is not match\nfrom id_token: %s\ncalculated: %s", idToken.AccessTokenHash, token.TokenHash(fragment.Get("access_token")))
				}
			},
		},
		{
			Name: "success / code id_token",
			Request: url.Values{
				"request":  {implicitRequest("code id_token", "openid", "")},
				"username": {"macrat"},
				"password": {"foobar"},
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

				if idToken, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
					t.Errorf("failed to parse id_token: %s", err)
				} else if idToken.CodeHash != token.TokenHash(fragment.Get("code")) {
					t.Errorf("c_hash is not match\nfrom id_token: %s\ncalculated: %s", idToken.CodeHash, token.TokenHash(fragment.Get("code")))
				}
			},
		},
	})
}
