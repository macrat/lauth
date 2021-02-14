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
	"github.com/macrat/lauth/token"
)

func TestLogout(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	ssoToken, err := env.API.TokenManager.CreateSSOToken(
		env.API.Config.Issuer,
		"macrat",
		token.AuthorizedParties{"some_client_id"},
		time.Now(),
		time.Now().Add(10*time.Minute),
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

	notLoggedInClientToken, err := env.API.TokenManager.CreateIDToken(
		env.API.Config.Issuer,
		"macrat",
		"implicit_client_id",
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
		Name        string
		Request     url.Values
		Code        int
		State       string
		NotLoggedIn bool
		Logout      bool
		Message     string
	}{
		{
			Name:    "no query",
			Request: url.Values{},
			Code:    http.StatusBadRequest,
			Logout:  false,
			Message: "id_token_hint is required in this OP",
		},
		{
			Name: "invalid token",
			Request: url.Values{
				"id_token_hint": {"invalid_id_token"},
			},
			Code:    http.StatusBadRequest,
			Logout:  false,
			Message: "invalid id_token_hint",
		},
		{
			Name: "another issuer token",
			Request: url.Values{
				"id_token_hint": {invalidToken},
			},
			Code:    http.StatusBadRequest,
			Logout:  false,
			Message: "invalid id_token_hint",
		},
		{
			Name: "client not registered",
			Request: url.Values{
				"id_token_hint": {anotherClientToken},
			},
			Code:    http.StatusBadRequest,
			Logout:  false,
			Message: "client is not registered",
		},
		{
			Name: "client not logged in",
			Request: url.Values{
				"id_token_hint": {notLoggedInClientToken},
			},
			Code:    http.StatusBadRequest,
			Logout:  false,
			Message: "user not logged in",
		},
		{
			Name: "invalid redirect URI",
			Request: url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"::invalid"},
			},
			Code:    http.StatusBadRequest,
			Logout:  false,
			Message: "post_logout_redirect_uri is invalid format",
		},
		{
			Name: "relative redirect URI",
			Request: url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"/path/to/somewhere"},
			},
			Code:    http.StatusBadRequest,
			Logout:  false,
			Message: "post_logout_redirect_uri is must be absolute URL",
		},
		{
			Name: "not registered URI",
			Request: url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"https://example.com/non/registered"},
			},
			Code:    http.StatusBadRequest,
			Logout:  false,
			Message: "post_logout_redirect_uri is not registered",
		},
		{
			Name: "user not logged in",
			Request: url.Values{
				"id_token_hint": {idToken},
			},
			Code:        http.StatusBadRequest,
			NotLoggedIn: true,
			Logout:      false,
			Message:     "user not logged in",
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
			t.Run(fmt.Sprintf("%s/%s", method, tt.Name), func(t *testing.T) {
				var req *http.Request
				if method == "GET" {
					var err error
					req, err = http.NewRequest("GET", "/logout?"+tt.Request.Encode(), nil)
					if err != nil {
						t.Fatalf("failed to prepare test request: %s", err)
					}
				} else {
					var err error
					req, err = http.NewRequest("POST", "/logout", strings.NewReader(tt.Request.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					if err != nil {
						t.Fatalf("failed to prepare test request: %s", err)
					}
				}
				if !tt.NotLoggedIn {
					req.Header.Set("Cookie", fmt.Sprintf("%s=%s", api.SSO_TOKEN_COOKIE, ssoToken))
				}
				resp := env.DoRequest(req)

				if resp.Code != tt.Code {
					t.Fatalf("expected status code is %d but got %d", tt.Code, resp.Code)
				}

				if tt.Message != "" && !strings.Contains(string(resp.Body.Bytes()), tt.Message) {
					t.Log(string(resp.Body.Bytes()))
					t.Errorf("expected message %#v was not contained in the response", tt.Message)
				}

				h := http.Header{}
				h.Add("Cookie", resp.Header().Get("Set-Cookie"))
				r := http.Request{Header: h}
				if tt.Logout {
					if c, err := r.Cookie(api.SSO_TOKEN_COOKIE); err != nil {
						t.Errorf("failed to get token cookie: %s", err)
					} else if c.Value != "" {
						t.Errorf("expected logout but token cookie has value %#v", c.Value)
					} else if c.MaxAge > 0 {
						t.Errorf("expected logout but token cookie has positive max-age (had %d)", c.MaxAge)
					}
				} else {
					if c, err := r.Cookie(api.SSO_TOKEN_COOKIE); err == nil {
						t.Errorf("%s %s: expected failed to logout but token cookie is set: %s", method, tt.Name, c)
					}
				}

				if tt.Logout && tt.Code == http.StatusFound {
					if rawLoc := resp.Header().Get("Location"); rawLoc == "" {
						t.Errorf("expected redirect but location is empty")
					} else if loc, err := url.Parse(rawLoc); err != nil {
						t.Errorf("failed to parse location: %s", err)
					} else if loc.Query().Get("state") != tt.Request.Get("state") {
						t.Errorf("expected state %#v but got %#v", tt.Request.Get("state"), loc.Query().Get("state"))
					}
				}
			})
		}
	}
}
