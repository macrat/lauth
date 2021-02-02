package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/macrat/lauth/testutil"
)

func TestGetUserinfo(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

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

	env.JSONTest(t, "GET", "/userinfo", []testutil.JSONTest{
		{
			Token: "Bearer " + noScopeToken,
			Code:  http.StatusOK,
			Body: map[string]interface{}{
				"sub": "macrat",
			},
		},
		{
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
			Token: "Bearer invalid token",
			Code:  http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "token is invalid",
			},
		},
		{
			Code: http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "bearer token is required",
			},
		},
		{
			Token: "Basic c29tZV9jbGllbnRfaWQ6c2VjcmV0IGZvciBzb21lLWNsaWVudA==",
			Code:  http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "bearer token is required",
			},
		},
		{
			Token: "Bearer " + nobodyToken,
			Code:  http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "user was not found or disabled",
			},
		},
	})
}
