package api_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/macrat/lauth/api"
	"github.com/macrat/lauth/testutil"
	"github.com/macrat/lauth/token"
)

func TestGetAuthz(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	requestURI := env.ServeRequestURI(t)
	defer requestURI.Close()

	env.RedirectTest(t, "GET", "/authz", authzEndpointCommonTests(t, env.API.Config))

	env.RedirectTest(t, "GET", "/authz", []testutil.RedirectTest{
		{
			Name: "success / code",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code: http.StatusOK,
		},
		{
			Name: "success / code token",
			Request: url.Values{
				"redirect_uri":  {"http://implicit-client.example.com/callback"},
				"client_id":     {"implicit_client_id"},
				"response_type": {"code token"},
			},
			Code: http.StatusOK,
		},
		{
			Name: "success / request object",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss":           "some_client_id",
					"aud":           env.API.Config.Issuer.String(),
					"client_id":     "some_client_id",
					"response_type": "code",
					"redirect_uri":  "http://some-client.example.com/callback",
				})},
			},
			Code: http.StatusOK,
		},
		{
			Name: "success / request_uri",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request_uri":   {requestURI.URL + "/some-client/correct"},
			},
			Code: http.StatusOK,
		},
		{
			Name: "missing client_id",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"response_type": {"code"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request", "client_id is required"},
		},
		{
			Name: "missing response_type",
			Request: url.Values{
				"redirect_uri": {"http://some-client.example.com/callback"},
				"client_id":    {"some_client_id"},
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
			Name: "unknown response_type",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
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
			Name: "relative redirect_uri",
			Request: url.Values{
				"redirect_uri":  {"/invalid/relative/url"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request", "redirect_uri is must be absolute URL"},
		},
		{
			Name: "not registered client_id",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"another_client_id"},
				"response_type": {"code"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_client", "client_id is not registered"},
		},
		{
			Name: "not registered redirect_uri",
			Request: url.Values{
				"redirect_uri":  {"http://other-site.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"unauthorized_client", "redirect_uri is not registered"},
		},
		{
			Name: "missing redirect_uri",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request", "redirect_uri is required"},
		},
		{
			Name: "invalid redirect_uri",
			Request: url.Values{
				"redirect_uri":  {"this is invalid url::"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request", "redirect_uri is invalid format"},
		},
		{
			Name: "disallowed hybrid flow",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code token"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query:       url.Values{},
			Fragment: url.Values{
				"error":             {"unsupported_response_type"},
				"error_description": {"implicit/hybrid flow is disallowed"},
			},
		},
		{
			Name: "request object / mismatch some values",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"scope":         {"openid profile"},
				"state":         {"this is state"},
				"nonce":         {"this is nonce"},
				"max_age":       {"123"},
				"prompt":        {"login"},
				"login_hint":    {"macrat"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss":           "some_client_id",
					"aud":           env.API.Config.Issuer.String(),
					"client_id":     "another_client_id",
					"response_type": "token",
					"redirect_uri":  "http://another-client.example.com/callback",
					"scope":         "openid profile email",
					"state":         "this is another state",
					"nonce":         "this is nonce",
					"max_age":       123,
					"prompt":        "login",
					"login_hint":    "macrat",
				})},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_request_object"},
				"error_description": {"mismatch query parameter and request object: response_type, client_id, redirect_uri, scope, state"},
				"state":             {"this is state"},
			},
			Fragment: url.Values{},
		},
		{
			Name: "request object / mismatch another some values",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"scope":         {"openid profile"},
				"state":         {"this is state"},
				"nonce":         {"this is nonce"},
				"max_age":       {"123"},
				"prompt":        {"login"},
				"login_hint":    {"macrat"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss":           "some_client_id",
					"aud":           env.API.Config.Issuer.String(),
					"client_id":     "some_client_id",
					"response_type": "code",
					"redirect_uri":  "http://some-client.example.com/callback",
					"scope":         "openid profile",
					"state":         "this is state",
					"nonce":         "this is anothernonce",
					"max_age":       42,
					"prompt":        "consent",
					"login_hint":    "j.smith",
				})},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_request_object"},
				"error_description": {"mismatch query parameter and request object: nonce, max_age, prompt, login_hint"},
				"state":             {"this is state"},
			},
			Fragment: url.Values{},
		},
		{
			Name: "request object / invalid redirect_uri",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss":          "some_client_id",
					"aud":          env.API.Config.Issuer.String(),
					"redirect_uri": "this is invalid url::",
				})},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Name: "request object / set both of prompt=none and prompt=login",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss":          "some_client_id",
					"aud":          env.API.Config.Issuer.String(),
					"redirect_uri": "http://some-client.example.com/callback",
					"prompt":       "none login",
				})},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"prompt=none can't use same time with login, select_account, or consent"},
			},
			Fragment: url.Values{},
		},
		{
			Name: "request object / expired",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss":          "some_client_id",
					"aud":          env.API.Config.Issuer.String(),
					"exp":          time.Now().Add(-10 * time.Minute).Unix(),
					"redirect_uri": "http://some-client.example.com/callback",
				})},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request_object", "failed to decode or validation request object"},
		},
		{
			Name: "request_uri / not found",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request_uri":   {requestURI.URL + "/not-found"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request_uri", "failed to fetch request object from request_uri"},
		},
		{
			Name: "request_uri / empty response",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request_uri":   {requestURI.URL + "/empty"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request_uri", "failed to fetch request object from request_uri"},
		},
		{
			Name: "request_uri / server error",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request_uri":   {requestURI.URL + "/server-error"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request_uri", "failed to fetch request object from request_uri"},
		},
		{
			Name: "request_uri / response is not jwt",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request_uri":   {requestURI.URL + "/not-jwt"},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request_uri", "failed to decode or validation request object"},
		},
		{
			Name: "both of request and request_uri",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request_uri":   {requestURI.URL + "/some-client/correct"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss":          "some_client_id",
					"aud":          env.API.Config.Issuer.String(),
					"redirect_uri": "http://some-client.example.com/callback",
				})},
			},
			Code:         http.StatusBadRequest,
			HasLocation:  false,
			BodyIncludes: []string{"invalid_request", "can&#39;t use both of request and request_uri in same time"},
		},
		{
			Name: "missing nonce in implicit flow",
			Request: url.Values{
				"redirect_uri":  {"http://implicit-client.example.com/callback"},
				"client_id":     {"implicit_client_id"},
				"response_type": {"token id_token"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query:       url.Values{},
			Fragment: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"nonce is required in the implicit/hybrid flow of OpenID Connect"},
			},
		},
		{
			Name: "can't use both prompt of none and login",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"prompt":        {"none login"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"prompt=none can't use same time with login, select_account, or consent"},
			},
			Fragment: url.Values{},
		},
		{
			Name: "can't use both prompt of none and consent",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"prompt":        {"consent none"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"prompt=none can't use same time with login, select_account, or consent"},
			},
			Fragment: url.Values{},
		},
		{
			Name: "can't use both prompt of none and select_account",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"prompt":        {"none select_account"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"prompt=none can't use same time with login, select_account, or consent"},
			},
			Fragment: url.Values{},
		},
		{
			Name: "prompt=none but not logged in",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"prompt":        {"none"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error": {"login_required"},
			},
			Fragment: url.Values{},
		},
		{
			Name: "given username and password",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"username":      {"macrat"},
				"password":      {"foobar"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"can't set username or password in GET method"},
			},
			Fragment: url.Values{},
		},
	})
}

func TestGetAuthz_LoginExpires(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	tests := []struct {
		Name       string
		RequestTTL time.Duration
		ExpectTTL  time.Duration
	}{
		{
			Name:       "short expire",
			RequestTTL: 1 * time.Minute,
			ExpectTTL:  1 * time.Minute,
		},
		{
			Name:       "long expire",
			RequestTTL: 24 * time.Hour,
			ExpectTTL:  env.API.Config.Expire.Login.Duration(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			requestExpires := time.Now().Add(tt.RequestTTL).Unix()
			expectedExpires := time.Now().Add(tt.ExpectTTL).Unix()

			resp := env.Get("/authz", "", url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss":           "some_client_id",
					"aud":           env.API.Config.Issuer.String(),
					"exp":           requestExpires,
					"client_id":     "some_client_id",
					"response_type": "code",
					"redirect_uri":  "http://some-client.example.com/callback",
				})},
			})
			if resp.Code != http.StatusOK {
				t.Fatalf("unexpected status code: %d", resp.Code)
			}

			inputs, err := testutil.FindInputsByHTML(resp.Body)
			if err != nil {
				t.Fatalf("failed to get inputs: %s", err)
			}

			claims, err := env.API.TokenManager.ParseRequestObject(inputs["request"], "")
			if err != nil {
				t.Fatalf("failed to parse request object: %s", err)
			}

			if claims.ExpiresAt != expectedExpires {
				t.Errorf("unexpected request object duration: %s", time.Unix(claims.ExpiresAt, 0))
			}
		})
	}
}

func TestGetAuthz_SSO(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	invalidToken, err := env.API.TokenManager.CreateIDToken(
		env.API.Config.Issuer,
		"macrat",
		"another_cilent_id",
		"",
		"",
		"",
		nil,
		time.Now().Add(-5*time.Minute),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create SSO token: %s", err)
	}

	tests := []struct {
		Name     string
		Request  url.Values
		AuthTime time.Time
		Token    string
		CanSSO   bool
	}{
		{
			Name: "logged in at 5m ago",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			AuthTime: time.Now().Add(-5 * time.Minute),
			CanSSO:   true,
		},
		{
			Name: "logged in at 11m ago",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			AuthTime: time.Now().Add(-11 * time.Minute),
			CanSSO:   true,
		},
		{
			Name: "logged in at 5m ago / prompt=none",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"prompt":        {"none"},
			},
			AuthTime: time.Now().Add(-5 * time.Minute),
			CanSSO:   true,
		},
		{
			Name: "logged in at 5m ago / prompt=login",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"prompt":        {"login"},
			},
			AuthTime: time.Now().Add(-5 * time.Minute),
			CanSSO:   false,
		},
		{
			Name: "logged in at 5m ago / prompt=consent",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"prompt":        {"consent"},
			},
			AuthTime: time.Now().Add(-5 * time.Minute),
			CanSSO:   false,
		},
		{
			Name: "logged in at 5m ago / prompt=select_account",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"prompt":        {"select_account"},
			},
			AuthTime: time.Now().Add(-5 * time.Minute),
			CanSSO:   false,
		},
		{
			Name: "logged in at 5m ago / max_age=360",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"max_age":       {"360"},
			},
			AuthTime: time.Now().Add(-5 * time.Minute),
			CanSSO:   true,
		},
		{
			Name: "logged in at 5m ago / max_age=240",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"max_age":       {"240"},
			},
			AuthTime: time.Now().Add(-5 * time.Minute),
			CanSSO:   false,
		},
		{
			Name: "invalid token (can't parse)",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Token:  "this is invalid token",
			CanSSO: false,
		},
		{
			Name: "invalid token (invalid value)",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"max_age":       {"240"},
			},
			Token:  invalidToken,
			CanSSO: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ssoToken := tt.Token
			if ssoToken == "" {
				var err error
				ssoToken, err = env.API.TokenManager.CreateSSOToken(
					env.API.Config.Issuer,
					"macrat",
					token.AuthorizedParties{"some_client_id"},
					tt.AuthTime,
					time.Now().Add(10*time.Minute),
				)
				if err != nil {
					t.Fatalf("failed to create SSO token: %s", err)
				}
			}

			req, _ := http.NewRequest("GET", "/authz?"+tt.Request.Encode(), nil)
			req.Header.Set("Cookie", fmt.Sprintf("%s=%s", api.SSO_TOKEN_COOKIE, ssoToken))
			resp := env.DoRequest(req)

			if !tt.CanSSO {
				if resp.Code != http.StatusOK {
					t.Fatalf("expect non SSO login but failed (status code = %d)", resp.Code)
				}
				return
			}

			if resp.Code != http.StatusFound {
				t.Fatalf("expect SSO login but failed (status code = %d)", resp.Code)
			}

			location, err := url.Parse(resp.Header().Get("Location"))
			if err != nil {
				t.Fatalf("failed to parse location header: %s", err)
			}

			query := location.Query()

			if query.Get("code") == "" {
				t.Errorf("expected returns code but not set")
			} else if code, err := env.API.TokenManager.ParseCode(query.Get("code")); err != nil {
				t.Errorf("failed to parse code: %s", err)
			} else if err := code.Validate(env.API.Config.Issuer); err != nil {
				t.Errorf("failed to validate code: %s", err)
			} else if code.AuthTime != int64(tt.AuthTime.Unix()) {
				t.Errorf("expected auth_time is %d but got %d", tt.AuthTime.Unix(), code.AuthTime)
			} else if code.Subject != "macrat" {
				t.Errorf("expected sub is \"macrat\" but got %s", code.Subject)
			}
		})
	}

	t.Run("can't use self issued request object for GET method", func(t *testing.T) {
		resp := env.Get("/authz", "", url.Values{
			"redirect_uri":  {"http://some-client.example.com/callback"},
			"client_id":     {"some_client_id"},
			"response_type": {"code"},
		})
		if resp.Code != http.StatusOK {
			t.Fatalf("failed to get request object: status code=%d", resp.Code)
		}

		request, err := testutil.FindRequestObjectByHTML(resp.Body)
		if err != nil {
			t.Fatalf("failed to get request object: %s", err)
		}

		resp = env.Get("/authz", "", url.Values{
			"redirect_uri":  {"http://some-client.example.com/callback"},
			"client_id":     {"some_client_id"},
			"response_type": {"code"},
			"request":       {request},
		})
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("unexpected status code: %d", resp.Code)
		}

		if !strings.Contains(string(resp.Body.Bytes()), "invalid_request_object") {
			t.Log(string(resp.Body.Bytes()))
			t.Errorf("expected error message \"invalid_request_object\" was not included in response body")
		}
	})
}
