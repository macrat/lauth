package api_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/macrat/lauth/api"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
)

func TestLogout(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	ssoToken, err := env.API.TokenManager.CreateIDToken(
		env.API.Config.Issuer,
		"macrat",
		env.API.Config.Issuer.String(),
		"",
		"",
		"",
		nil,
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create test id_token: %s", err)
	}

	idToken, err := env.API.TokenManager.CreateIDToken(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"",
		"",
		"",
		nil,
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create test id_token: %s", err)
	}

	anotherClientToken, err := env.API.TokenManager.CreateIDToken(
		env.API.Config.Issuer,
		"macrat",
		"another_client_id",
		"",
		"",
		"",
		nil,
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create test id_token: %s", err)
	}

	anotherUserToken, err := env.API.TokenManager.CreateIDToken(
		env.API.Config.Issuer,
		"someone",
		"some_client_id",
		"",
		"",
		"",
		nil,
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create test id_token: %s", err)
	}

	invalidToken, err := env.API.TokenManager.CreateIDToken(
		&config.URL{Scheme: "https", Host: "another-issuer.example.com"},
		"macrat",
		"some_client_id",
		"",
		"",
		"",
		nil,
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create test id_token: %s", err)
	}

	tests := []struct {
		Name              string
		Request           url.Values
		DisableClientAuth bool
		Code              int
		State             string
		NotLoggedIn       bool
		Logout            bool
	}{
		{
			Name:    "no query",
			Request: url.Values{},
			Code:    http.StatusBadRequest,
			Logout:  false,
		},
		{
			Name:              "no query / disable client auth",
			Request:           url.Values{},
			DisableClientAuth: true,
			Code:              http.StatusBadRequest,
			Logout:            false,
		},
		{
			Name: "invalid token",
			Request: url.Values{
				"id_token_hint": {"invalid_id_token"},
			},
			Code:   http.StatusBadRequest,
			Logout: false,
		},
		{
			Name: "invalid token / disable client auth",
			Request: url.Values{
				"id_token_hint": {"invalid_id_token"},
			},
			DisableClientAuth: true,
			Code:              http.StatusBadRequest,
			Logout:            false,
		},
		{
			Name: "another issuer token",
			Request: url.Values{
				"id_token_hint": {invalidToken},
			},
			Code:   http.StatusBadRequest,
			Logout: false,
		},
		{
			Name: "client not registered",
			Request: url.Values{
				"id_token_hint": {anotherClientToken},
			},
			Code:   http.StatusBadRequest,
			Logout: false,
		},
		{
			Name: "client not registered / disable client auth",
			Request: url.Values{
				"id_token_hint": {anotherClientToken},
			},
			DisableClientAuth: true,
			Code:              http.StatusOK,
			Logout:            true,
		},
		{
			Name: "invalid redirect URI",
			Request: url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"::invalid"},
			},
			Code:   http.StatusBadRequest,
			Logout: false,
		},
		{
			Name: "invalid redirect URI / disable client auth",
			Request: url.Values{
				"id_token_hint":            {anotherClientToken},
				"post_logout_redirect_uri": {"::invalid"},
			},
			DisableClientAuth: true,
			Code:              http.StatusBadRequest,
			Logout:            false,
		},
		{
			Name: "relative redirect URI",
			Request: url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"/path/to/somewhere"},
			},
			Code:   http.StatusBadRequest,
			Logout: false,
		},
		{
			Name: "relative redirect URI / disable client auth",
			Request: url.Values{
				"id_token_hint":            {anotherClientToken},
				"post_logout_redirect_uri": {"/path/to/somewhere"},
			},
			DisableClientAuth: true,
			Code:              http.StatusBadRequest,
			Logout:            false,
		},
		{
			Name: "not registered URI",
			Request: url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"https://example.com/non/registered"},
			},
			Code:   http.StatusBadRequest,
			Logout: false,
		},
		{
			Name: "not registered URI / disable client auth",
			Request: url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"https://example.com/non/registered"},
			},
			DisableClientAuth: true,
			Code:              http.StatusBadRequest,
			Logout:            false,
		},
		{
			Name: "user not logged in",
			Request: url.Values{
				"id_token_hint": {idToken},
			},
			Code:        http.StatusBadRequest,
			NotLoggedIn: true,
			Logout:      false,
		},
		{
			Name: "logged in as an another user",
			Request: url.Values{
				"id_token_hint": {anotherUserToken},
			},
			Code:   http.StatusBadRequest,
			Logout: false,
		},
		{
			Name: "non-redirect success with state",
			Request: url.Values{
				"id_token_hint": {idToken},
				"state":         {"this is a state"},
			},
			Code:   http.StatusOK,
			Logout: true,
		},
		{
			Name: "non-redirect success without state",
			Request: url.Values{
				"id_token_hint": {idToken},
			},
			Code:   http.StatusOK,
			Logout: true,
		},
		{
			Name: "redirect success with state",
			Request: url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"http://some-client.example.com/logout"},
				"state":                    {"this is a state"},
			},
			Code:   http.StatusFound,
			Logout: true,
		},
		{
			Name: "redirect success without state",
			Request: url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"http://some-client.example.com/logout"},
			},
			Code:   http.StatusFound,
			Logout: true,
		},
	}

	for _, method := range []string{"GET", "POST"} {
		for _, tt := range tests {
			env.API.Config.DisableClientAuth = tt.DisableClientAuth

			var req *http.Request
			if method == "GET" {
				var err error
				req, err = http.NewRequest("GET", "/logout?"+tt.Request.Encode(), nil)
				if err != nil {
					t.Fatalf("%s %s: failed to prepare test request: %s", method, tt.Name, err)
				}
			} else {
				var err error
				req, err = http.NewRequest("POST", "/logout", strings.NewReader(tt.Request.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if err != nil {
					t.Fatalf("%s %s: failed to prepare test request: %s", method, tt.Name, err)
				}
			}
			if !tt.NotLoggedIn {
				req.Header.Set("Cookie", fmt.Sprintf("%s=%s", api.SSO_TOKEN_COOKIE, ssoToken))
			}
			resp := env.DoRequest(req)

			if resp.Code != tt.Code {
				//t.Log(string(resp.Body.Bytes()))
				t.Errorf("%s %s: expected status code is %d but got %d", method, tt.Name, tt.Code, resp.Code)
				continue
			}

			h := http.Header{}
			h.Add("Cookie", resp.Header().Get("Set-Cookie"))
			r := http.Request{Header: h}
			if tt.Logout {
				if c, err := r.Cookie(api.SSO_TOKEN_COOKIE); err != nil {
					t.Errorf("%s %s: failed to get token cookie: %s", method, tt.Name, err)
				} else if c.Value != "" {
					t.Errorf("%s %s: expected logout but token cookie has value %#v", method, tt.Name, c.Value)
				} else if c.MaxAge > 0 {
					t.Errorf("%s %s: expected logout but token cookie has positive max-age (had %d)", method, tt.Name, c.MaxAge)
				}
			} else {
				if c, err := r.Cookie(api.SSO_TOKEN_COOKIE); err == nil {
					t.Errorf("%s %s: expected failed to logout but token cookie is set: %s", method, tt.Name, c)
				}
			}

			if tt.Logout && tt.Code == http.StatusFound {
				if rawLoc := resp.Header().Get("Location"); rawLoc == "" {
					t.Errorf("%s %s: expected redirect but location is empty", method, tt.Name)
				} else if loc, err := url.Parse(rawLoc); err != nil {
					t.Errorf("%s %s: failed to parse location: %s", method, tt.Name, err)
				} else if loc.Query().Get("state") != tt.Request.Get("state") {
					t.Errorf("%s %s: expected state %#v but got %#v", method, tt.Name, tt.Request.Get("state"), loc.Query().Get("state"))
				}
			}
		}
	}
}
