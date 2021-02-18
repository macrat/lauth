package api_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/macrat/lauth/api"
	"github.com/macrat/lauth/testutil"
	"github.com/macrat/lauth/token"
)

func TestGetAuthz(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

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
			"client_id":     {"some_client_id"},
			"response_type": {"code"},
			"request":       {request},
		})
		if resp.Code != http.StatusFound {
			t.Fatalf("unexpected status code: %d", resp.Code)
		}

		location, err := url.Parse(resp.Header().Get("Location"))
		if err != nil {
			t.Errorf("failed to parse location: %s", err)
		}

		if errMsg := location.Query().Get("error"); errMsg != "invalid_request_object" {
			t.Errorf("unexpected error message: %#v", errMsg)
		}
		if desc := location.Query().Get("error_description"); desc != "invalid request object for GET method" {
			t.Errorf("unexpected error description: %#v", desc)
		}
	})
}
