package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/macrat/ldapin/testutil"
)

func TestGetUserinfo(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	noScopeToken, err := env.API.JWTManager.CreateAccessToken(
		env.API.Config.Issuer,
		"macrat",
		"openid",
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to generate access_token: %s", err)
	}

	multiScopeToken, err := env.API.JWTManager.CreateAccessToken(
		env.API.Config.Issuer,
		"macrat",
		"openid profile email",
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to generate access_token: %s", err)
	}

	nobodyToken, err := env.API.JWTManager.CreateAccessToken(
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
			Token: noScopeToken,
			Code:  http.StatusOK,
			Body: map[string]interface{}{
				"sub": "macrat",
			},
		},
		{
			Token: multiScopeToken,
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
			Token: "invalid token",
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
			Token: nobodyToken,
			Code:  http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "user was not found or disabled",
			},
		},
	})
}
