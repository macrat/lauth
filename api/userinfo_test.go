package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/macrat/lauth/testutil"
)

func UserInfoCommonTests(t *testing.T, env *testutil.APITestEnvironment) []testutil.JSONTest {
	noScopeToken, err := env.API.TokenManager.CreateAccessToken(
		env.API.Config.Issuer,
		"macrat",
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
