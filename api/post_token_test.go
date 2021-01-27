package api_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/macrat/ldapin/api"
	"github.com/macrat/ldapin/config"
	"github.com/macrat/ldapin/testutil"
)

func TestPostToken(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	code, err := env.API.JWTManager.CreateCode(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"openid profile",
		"something-nonce",
		time.Now(),
		time.Duration(env.API.Config.TTL.Code),
	)
	if err != nil {
		t.Fatalf("failed to generate test code: %s", err)
	}

	invalidCode, err := env.API.JWTManager.CreateCode(
		&config.URL{Host: "another_issuer"},
		"macrat",
		"some_client_id",
		"openid profile",
		"",
		time.Now(),
		time.Duration(env.API.Config.TTL.Code),
	)
	if err != nil {
		t.Fatalf("failed to generate test code: %s", err)
	}

	env.JSONTest(t, "POST", "/token", []testutil.JSONTest{
		{
			Request: url.Values{
				"grant_type": {"invalid_grant_type"},
				"code":       {code},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "unsupported_grant_type",
				"error_description": "only supported grant_type is authorization_code",
			},
		},
		{
			Request: url.Values{
				"grant_type": {"authorization_code"},
				"code":       {"invalid-code"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_grant",
			},
		},
		{
			Request: url.Values{
				"grant_type": {"authorization_code"},
				"code":       {invalidCode},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_grant",
			},
		},
		{
			Request: url.Values{
				"grant_type": {"authorization_code"},
				"code":       {code},
			},
			Code: http.StatusOK,
			CheckBody: func(t *testing.T, body testutil.RawBody) {
				var resp api.PostTokenResponse
				if err := body.Bind(&resp); err != nil {
					t.Errorf("failed to unmarshal response body: %s", err)
					return
				}

				if resp.TokenType != "Bearer" {
					t.Errorf("token_type is expected \"Bearer\" but got %#v", resp.TokenType)
				}

				if resp.ExpiresIn != 3600 {
					t.Errorf("expires_in is expected 3600 but got %#v", resp.ExpiresIn)
				}

				if resp.Scope != "openid profile" {
					t.Errorf("scope is expected \"openid profile\" but got %#v", resp.Scope)
				}

				accessToken, err := env.API.JWTManager.ParseAccessToken(resp.AccessToken)
				if err != nil {
					t.Errorf("failed to parse access token: %s", err)
				}
				if err = accessToken.Validate(env.API.Config.Issuer); err != nil {
					t.Errorf("failed to validate access token: %s", err)
				}

				idToken, err := env.API.JWTManager.ParseIDToken(resp.IDToken)
				if err != nil {
					t.Errorf("failed to parse id token: %s", err)
				}
				if err = idToken.Validate(env.API.Config.Issuer, "some_client_id"); err != nil {
					t.Errorf("failed to validate id token: %s", err)
				}
				if idToken.Nonce != "something-nonce" {
					t.Errorf("nonce must be \"something-nonce\" but got %#v", idToken.Nonce)
				}
			},
		},
	})
}
