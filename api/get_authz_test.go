package api_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/macrat/lauth/api"
	"github.com/macrat/lauth/testutil"
)

func TestGetAuthz(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	env.RedirectTest(t, "GET", "/authz", authzEndpointCommonTests)

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
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code token"},
			},
			AllowImplicit: true,
			Code:          http.StatusOK,
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
	})
}

func TestGetAuthz_SSO(t *testing.T) {
	tests := []struct {
		Name     string
		Request  url.Values
		AuthTime time.Time
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
	}

	env := testutil.NewAPITestEnvironment(t)

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ssoToken, err := env.API.TokenManager.CreateIDToken(
				env.API.Config.Issuer,
				"macrat",
				env.API.Config.Issuer.String(),
				"",
				"",
				"",
				nil,
				tt.AuthTime,
				10*time.Minute,
			)
			if err != nil {
				t.Fatalf("failed to create SSO token: %s", err)
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
}

func TestGetAuthz_AnonymousClients(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)
	env.API.Config.DisableClientAuth = true

	env.RedirectTest(t, "GET", "/authz", []testutil.RedirectTest{
		{
			Name: "not registered client_id",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"another_client_id"},
				"response_type": {"code"},
			},
			Code:        http.StatusOK,
			HasLocation: false,
		},
		{
			Name: "registered client_id and not registered redirect_uri",
			Request: url.Values{
				"redirect_uri":  {"http://other-site.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code:        http.StatusBadRequest,
			HasLocation: false,
		},
		{
			Name: "not registered both of client_id and redirect_uri",
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"another_client_id"},
				"response_type": {"code"},
			},
			Code:        http.StatusOK,
			HasLocation: false,
		},
	})
}
