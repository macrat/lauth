package api_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/macrat/ldapin/testutil"
)

func TestGetAuthz(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	env.RedirectTest(t, "GET", "/authz", authzEndpointCommonTests)

	env.RedirectTest(t, "GET", "/authz", []testutil.RedirectTest{
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			Code: http.StatusOK,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code token"},
			},
			AllowImplicit: true,
			Code:          http.StatusOK,
		},
		{
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
		Request  url.Values
		AuthTime time.Time
		CanSSO   bool
	}{
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			AuthTime: time.Now().Add(-5 * time.Minute),
			CanSSO:   true,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"some_client_id"},
				"response_type": {"code"},
			},
			AuthTime: time.Now().Add(-11 * time.Minute),
			CanSSO:   true,
		},
		{
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

	for i, tt := range tests {
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
			t.Errorf("%d: failed to create SSO token: %s", i, err)
			continue
		}

		req, _ := http.NewRequest("GET", "/authz?"+tt.Request.Encode(), nil)
		req.Header.Set("Cookie", fmt.Sprintf("token=%s", ssoToken))
		resp := env.DoRequest(req)

		if !tt.CanSSO {
			if resp.Code != http.StatusOK {
				t.Errorf("test %d expect non SSO login but failed (status code = %d)", i, resp.Code)
			}
			continue
		}

		if resp.Code != http.StatusFound {
			t.Errorf("test %d expect SSO login but failed (status code = %d)", i, resp.Code)
			continue
		}

		location, err := url.Parse(resp.Header().Get("Location"))
		if err != nil {
			t.Errorf("%d: failed to parse location header: %s", i, err)
			continue
		}

		query := location.Query()

		if query.Get("code") == "" {
			t.Errorf("%d: expected returns code but not set", i)
		} else if code, err := env.API.TokenManager.ParseCode(query.Get("code")); err != nil {
			t.Errorf("%d: failed to parse code: %s", i, err)
		} else if err := code.Validate(env.API.Config.Issuer); err != nil {
			t.Errorf("%d: failed to validate code: %s", i, err)
		} else if code.AuthTime != int64(tt.AuthTime.Unix()) {
			t.Errorf("%d: expected auth_time is %d but got %d", i, tt.AuthTime.Unix(), code.AuthTime)
		} else if code.Subject != "macrat" {
			t.Errorf("%d: expected sub is \"macrat\" but got %s", i, code.Subject)
		}
	}
}

func TestGetAuthz_AnonymousClients(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)
	env.API.Config.DisableClientAuth = true

	env.RedirectTest(t, "GET", "/authz", []testutil.RedirectTest{
		{
			Request: url.Values{
				"redirect_uri":  {"http://some-client.example.com/callback"},
				"client_id":     {"another_client_id"},
				"response_type": {"code"},
			},
			Code:        http.StatusOK,
			HasLocation: false,
		},
		{
			Request: url.Values{
				"redirect_uri":  {"http://other-site.example.com/callback"},
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
			Code:        http.StatusOK,
			HasLocation: false,
		},
	})
}
