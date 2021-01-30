package api_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/macrat/ldapin/testutil"
)

var (
	authzEndpointCommonTests = []testutil.RedirectTest{
		{
			Request:     url.Values{},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"response_type": {"code"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_client"},
				"error_description": {"client_id is required"},
			},
			Fragment: url.Values{},
		},
		{
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
			Request: url.Values{
				"redirect_uri":  {"/invalid/relative/url"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"another_client_id"},
				"response_type": {"code"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"invalid_client"},
				"error_description": {"client_id is not registered"},
			},
			Fragment: url.Values{},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://other-site.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code:        http.StatusFound,
			HasLocation: true,
			Query: url.Values{
				"error":             {"unauthorized_client"},
				"error_description": {"redirect_uri is not registered"},
			},
			Fragment: url.Values{},
		},
		{
			Request: url.Values{
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
			Query:       url.Values{},
			Fragment:    url.Values{},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"this is invalid url::"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
			Query:       url.Values{},
			Fragment:    url.Values{},
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code token"},
			},
			AllowImplicit: false,
			Code:          http.StatusFound,
			HasLocation:   true,
			Query:         url.Values{},
			Fragment: url.Values{
				"error":             {"unsupported_response_type"},
				"error_description": {"implicit/hybrid flow is disallowed in this server"},
			},
		},
	}
)

func TestSSO(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	resp := env.Post("/authz", "", url.Values{
		"redirect_uri":  {"http://some-client.example.com/callback"},
		"client_id":     {"some_client_id"},
		"response_type": {"code"},
		"username":      {"macrat"},
		"password":      {"foobar"},
	})
	if resp.Code != http.StatusFound {
		t.Fatalf("unexpected status code: %d", resp.Code)
	}
	rawCookie, ok := resp.Header()["Set-Cookie"]
	if !ok {
		t.Fatalf("cookies for SSO was not found")
	}

	cookie, _ := (&http.Request{Header: http.Header{"Cookie": rawCookie}}).Cookie("token")

	ssoToken, err := env.API.TokenManager.ParseIDToken(cookie.Value)
	if err != nil {
		t.Errorf("failed to parse token in cookie: %s", err)
	} else if err := ssoToken.Validate(env.API.Config.Issuer, env.API.Config.Issuer.String()); err != nil {
		t.Errorf("token in cookie is invalid: %s", err)
	}

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
		t.Fatalf("unexpected login with SSO token: %d", resp.Code)
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
}
