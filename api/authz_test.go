package api_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/macrat/lauth/api"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
)

func authzEndpointCommonTests(t *testing.T, c *config.Config) []testutil.RedirectTest {
	return []testutil.RedirectTest{
		{
			Name:        "without any query",
			Request:     url.Values{},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Name: "request object / can't parse",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request":       {"invalid request"},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Name: "request object / empty request",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"request":       {testutil.SomeClientRequestObject(t, map[string]interface{}{})},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Name: "request object / missing issuer",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"aud": c.Issuer.String(),
				})},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Name: "request object / missing audience",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss": "some_client_id",
				})},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Name: "request object / expired already",
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
					"iss": "some_client_id",
					"aud": c.Issuer.String(),
					"exp": 100,
				})},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
	}
}

func TestSSOLogin(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	t.Log("---------- first login ----------")

	resp := env.Get("/authz", "", url.Values{
		"redirect_uri":  {"http://some-client.example.com/callback"},
		"client_id":     {"some_client_id"},
		"response_type": {"code"},
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status code on first login: %d", resp.Code)
	}

	request, err := testutil.FindRequestObjectByHTML(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse first login page: %s", err)
	}

	resp = env.Post("/authz", "", url.Values{
		"client_id":     {"some_client_id"},
		"response_type": {"code"},
		"request":       {request},
		"username":      {"macrat"},
		"password":      {"foobar"},
	})
	if resp.Code != http.StatusFound {
		t.Fatalf("unexpected status code on first login: %d", resp.Code)
	}
	rawCookie, ok := resp.Header()["Set-Cookie"]
	if !ok {
		t.Fatalf("cookies for SSO was not found")
	}

	cookie, _ := (&http.Request{Header: http.Header{"Cookie": rawCookie}}).Cookie(api.SSO_TOKEN_COOKIE)

	ssoToken, err := env.API.TokenManager.ParseSSOToken(cookie.Value)
	if err != nil {
		t.Errorf("failed to parse token in cookie: %s", err)
	} else if err := ssoToken.Validate(env.API.Config.Issuer); err != nil {
		t.Errorf("token in cookie is invalid: %s", err)
	}

	t.Log("---------- login with SSO token ----------")

	params := url.Values{
		"redirect_uri":  {"http://some-client.example.com/callback"},
		"client_id":     {"some_client_id"},
		"response_type": {"code"},
	}
	req, _ := http.NewRequest("GET", "/authz?"+params.Encode(), nil)
	for _, c := range rawCookie {
		req.Header.Add("Cookie", c)
	}

	resp = env.DoRequest(req)
	if resp.Code != http.StatusFound {
		t.Fatalf("unexpected status code on login with SSO token: %d", resp.Code)
	}

	location, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Errorf("failed to parse location: %s", err)
	}
	code, err := env.API.TokenManager.ParseCode(location.Query().Get("code"))
	if err != nil {
		t.Errorf("failed to parse code: %s", err)
	} else if err = code.Validate(env.API.Config.Issuer); err != nil {
		t.Errorf("respond code is invalid: %s", err)
	} else if code.AuthTime != ssoToken.AuthTime {
		t.Errorf("auth_time is not match: sso_token=%d != code=%d", ssoToken.AuthTime, code.AuthTime)
	} else if code.Subject != ssoToken.Subject {
		t.Errorf("auth_time is not match: sso_token=%s != code=%s", ssoToken.Subject, code.Subject)
	}

	t.Log("---------- show consent prompt with SSO token ----------")

	params = url.Values{
		"redirect_uri":  {"http://some-client.example.com/callback"},
		"client_id":     {"some_client_id"},
		"response_type": {"code"},
		"prompt":        {"consent"},
	}
	req, _ = http.NewRequest("GET", "/authz?"+params.Encode(), nil)
	for _, c := range rawCookie {
		req.Header.Add("Cookie", c)
	}

	resp = env.DoRequest(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status code on prompt=consent with SSO token: %d", resp.Code)
	}

	inputs, err := testutil.FindInputsByHTML(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse consent page: %s", err)
	}

	if _, ok := inputs["username"]; ok {
		t.Errorf("expected consent page but got username input")
	}

	if _, ok := inputs["password"]; ok {
		t.Errorf("expected consent page but got password input")
	}

	t.Log("---------- login via consent prompt ----------")
	params = url.Values{}
	for k, v := range inputs {
		params.Add(k, v)
	}

	req, _ = http.NewRequest("POST", "/authz", strings.NewReader(params.Encode()))
	for _, c := range rawCookie {
		req.Header.Add("Cookie", c)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp = env.DoRequest(req)
	if resp.Code != http.StatusFound {
		t.Fatalf("unexpected status code on login via consent prompt: %d", resp.Code)
	}

	location, err = url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Errorf("failed to parse location: %s", err)
	}
	code, err = env.API.TokenManager.ParseCode(location.Query().Get("code"))
	if err != nil {
		t.Errorf("failed to parse code: %s", err)
	} else if err = code.Validate(env.API.Config.Issuer); err != nil {
		t.Errorf("respond code is invalid: %s", err)
	} else if code.AuthTime != ssoToken.AuthTime {
		t.Errorf("auth_time is not match: sso_token=%d != code=%d", ssoToken.AuthTime, code.AuthTime)
	} else if code.Subject != ssoToken.Subject {
		t.Errorf("auth_time is not match: sso_token=%s != code=%s", ssoToken.Subject, code.Subject)
	}

	t.Log("---------- try login by another client with SSO token ----------")

	params = url.Values{
		"redirect_uri":  {"http://implicit-client.example.com/callback"},
		"client_id":     {"implicit_client_id"},
		"response_type": {"code"},
	}
	req, _ = http.NewRequest("GET", "/authz?"+params.Encode(), nil)
	for _, c := range rawCookie {
		req.Header.Add("Cookie", c)
	}

	resp = env.DoRequest(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status code on another client with SSO token: %d", resp.Code)
	}

	inputs, err = testutil.FindInputsByHTML(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse consent page: %s", err)
	}

	if _, ok := inputs["username"]; ok {
		t.Errorf("expected consent page but got username input")
	}

	if _, ok := inputs["password"]; ok {
		t.Errorf("expected consent page but got password input")
	}

	params = url.Values{}
	for k, v := range inputs {
		params.Add(k, v)
	}

	req, _ = http.NewRequest("POST", "/authz", strings.NewReader(params.Encode()))
	for _, c := range rawCookie {
		req.Header.Add("Cookie", c)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp = env.DoRequest(req)
	if resp.Code != http.StatusFound {
		t.Fatalf("unexpected status code on login via consent prompt: %d", resp.Code)
	}

	location, err = url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Errorf("failed to parse location: %s", err)
	}
	code, err = env.API.TokenManager.ParseCode(location.Query().Get("code"))
	if err != nil {
		t.Errorf("failed to parse code: %s", err)
	} else if err = code.Validate(env.API.Config.Issuer); err != nil {
		t.Errorf("respond code is invalid: %s", err)
	} else if code.AuthTime != ssoToken.AuthTime {
		t.Errorf("auth_time is not match: sso_token=%d != code=%d", ssoToken.AuthTime, code.AuthTime)
	} else if code.Subject != ssoToken.Subject {
		t.Errorf("auth_time is not match: sso_token=%s != code=%s", ssoToken.Subject, code.Subject)
	}

	t.Log("---------- first client still can login with SSO token ----------")

	params = url.Values{
		"redirect_uri":  {"http://some-client.example.com/callback"},
		"client_id":     {"some_client_id"},
		"response_type": {"code"},
	}
	req, _ = http.NewRequest("GET", "/authz?"+params.Encode(), nil)
	for _, c := range rawCookie {
		req.Header.Add("Cookie", c)
	}

	resp = env.DoRequest(req)
	if resp.Code != http.StatusFound {
		t.Fatalf("unexpected status code on login with SSO token: %d", resp.Code)
	}

	location, err = url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Errorf("failed to parse location: %s", err)
	}
	code, err = env.API.TokenManager.ParseCode(location.Query().Get("code"))
	if err != nil {
		t.Errorf("failed to parse code: %s", err)
	} else if err = code.Validate(env.API.Config.Issuer); err != nil {
		t.Errorf("respond code is invalid: %s", err)
	} else if code.AuthTime != ssoToken.AuthTime {
		t.Errorf("auth_time is not match: sso_token=%d != code=%d", ssoToken.AuthTime, code.AuthTime)
	} else if code.Subject != ssoToken.Subject {
		t.Errorf("auth_time is not match: sso_token=%s != code=%s", ssoToken.Subject, code.Subject)
	}
}
