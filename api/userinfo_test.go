package api_test

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/macrat/lauth/testutil"
)

func UserInfoCommonTests(t *testing.T, env *testutil.APITestEnvironment) []testutil.JSONTest {
	noScopeToken, err := env.API.TokenManager.CreateAccessToken(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"openid",
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to generate access_token: %s", err)
	}

	multiScopeToken, err := env.API.TokenManager.CreateAccessToken(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"openid profile email",
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to generate access_token: %s", err)
	}

	nobodyToken, err := env.API.TokenManager.CreateAccessToken(
		env.API.Config.Issuer,
		"nobody",
		"some_client_id",
		"openid profile",
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to generate access_token: %s", err)
	}

	return []testutil.JSONTest{
		{
			Name:  "success without scope",
			Token: "Bearer " + noScopeToken,
			Code:  http.StatusOK,
			Body: map[string]interface{}{
				"sub": "macrat",
			},
		},
		{
			Name:  "success with multiple scopes",
			Token: "Bearer " + multiScopeToken,
			Code:  http.StatusOK,
			Body: map[string]interface{}{
				"sub":         "macrat",
				"name":        "SHIDA Yuuma",
				"given_name":  "yuuma",
				"family_name": "shida",
				"email":       "m@crat.jp",
			},
		},
		{
			Name:  "invalid bearer token",
			Token: "Bearer invalid token",
			Code:  http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "token is invalid",
			},
		},
		{
			Name: "no set authorization header",
			Code: http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "access token is required",
			},
		},
		{
			Name:  "set empty authorization header",
			Token: "",
			Code:  http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "access token is required",
			},
		},
		{
			Name:  "using basic auth",
			Token: "Basic c29tZV9jbGllbnRfaWQ6c2VjcmV0IGZvciBzb21lLWNsaWVudA==",
			Code:  http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "access token is required",
			},
		},
		{
			Name:  "not registered user token",
			Token: "Bearer " + nobodyToken,
			Code:  http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "user was not found or disabled",
			},
		},
	}
}

func TestUserinfoCORS(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			tests := []struct {
				Name     string
				ClientID string
				Origin   string
				Code     int
				CORS     string
			}{
				{
					Name:     "some_client without origin",
					ClientID: "some_client_id",
					Origin:   "",
					Code:     http.StatusOK,
					CORS:     "",
				},
				{
					Name:     " some_client with origin",
					ClientID: "some_client_id",
					Origin:   "http://some-client.example.com",
					Code:     http.StatusForbidden,
					CORS:     "",
				},
				{
					Name:     "implicit_client without origin",
					ClientID: "implicit_client_id",
					Origin:   "",
					Code:     http.StatusOK,
					CORS:     "",
				},
				{
					Name:     "implicit_client with origin that root domain",
					ClientID: "implicit_client_id",
					Origin:   "http://implicit-client.example.com",
					Code:     http.StatusOK,
					CORS:     "http://implicit-client.example.com",
				},
				{
					Name:     "implicit_client with origin that sub domain",
					ClientID: "implicit_client_id",
					Origin:   "http://subdomain.implicit-client.example.com",
					Code:     http.StatusOK,
					CORS:     "http://subdomain.implicit-client.example.com",
				},
				{
					Name:     "implicit_client with invalid origin",
					ClientID: "implicit_client_id",
					Origin:   "http://another-client.example.com",
					Code:     http.StatusForbidden,
					CORS:     "",
				},
			}

			for _, tt := range tests {
				t.Run(tt.Name, func(t *testing.T) {
					token, err := env.API.TokenManager.CreateAccessToken(
						env.API.Config.Issuer,
						"macrat",
						tt.ClientID,
						"openid",
						time.Now(),
						10*time.Minute,
					)
					if err != nil {
						t.Fatalf("failed to generate access_token: %s", err)
					}

					req, err := http.NewRequest(method, "/userinfo", bytes.NewReader([]byte{}))
					if err != nil {
						t.Fatalf("failed to generate request: %s", err)
					}

					req.Header.Set("Authorization", "Bearer "+token)
					if tt.Origin != "" {
						req.Header.Set("Origin", tt.Origin)
					}

					resp := env.DoRequest(req)
					t.Log(string(resp.Body.Bytes()))
					if resp.Code != tt.Code {
						t.Fatalf("status code: expected %d but got %d", tt.Code, resp.Code)
					}

					if cors := resp.Header().Get("Access-Control-Allow-Origin"); cors != tt.CORS {
						t.Fatalf("unexpected cors header: %#v", cors)
					}
				})
			}
		})
	}
}
