package api_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/macrat/lauth/testutil"
)

func TestPostUserInfo_withHeader(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	env.JSONTest(t, "POST", "/userinfo", UserInfoCommonTests(t, env))
}

func TestPostUserInfo_withBody(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	token, err := env.API.TokenManager.CreateAccessToken(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"openid email",
		time.Now(),
		10*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to generate access_token: %s", err)
	}

	env.JSONTest(t, "POST", "/userinfo", []testutil.JSONTest{
		{
			Name: "success",
			Request: url.Values{
				"access_token": {token},
			},
			Code: http.StatusOK,
			Body: map[string]interface{}{
				"sub":   "macrat",
				"email": "m@crat.jp",
			},
		},
		{
			Name: "invaild token",
			Request: url.Values{
				"access_token": {"hello world"},
			},
			Code: http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "token is invalid",
			},
		},
		{
			Name: "empty token",
			Request: url.Values{
				"access_token": {""},
			},
			Code: http.StatusForbidden,
			Body: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "access token is required",
			},
		},
	})
}
