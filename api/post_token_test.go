package api_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/macrat/lauth/api"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
	"github.com/macrat/lauth/token"
)

func TestPostToken(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	env.JSONTest(t, "POST", "/token", []testutil.JSONTest{
		{
			Name: "invalid grant type",
			Request: url.Values{
				"grant_type":    {"invalid_grant_type"},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "unsupported_grant_type",
				"error_description": "supported grant_type is authorization_code or refresh_token",
			},
		},
	})
}

func ResponseValidation(env *testutil.APITestEnvironment, scope, codeHash string) testutil.JSONTester {
	return func(t *testing.T, body testutil.RawBody) {
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

		if resp.Scope != scope {
			t.Errorf("scope is expected %#v but got %#v", scope, resp.Scope)
		}

		accessToken, err := env.API.TokenManager.ParseAccessToken(resp.AccessToken)
		if err != nil {
			t.Errorf("failed to parse access token: %s", err)
		}
		if err = accessToken.Validate(env.API.Config.Issuer); err != nil {
			t.Errorf("failed to validate access token: %s", err)
		}

		if !api.ParseStringSet(scope).Has("openid") {
			if resp.IDToken != "" {
				t.Errorf("openid is not includes in scope but got id_token")
			}
		} else {
			idToken, err := env.API.TokenManager.ParseIDToken(resp.IDToken)
			if err != nil {
				t.Errorf("failed to parse id token: %s", err)
			}
			if err = idToken.Validate(env.API.Config.Issuer, "some_client_id"); err != nil {
				t.Errorf("failed to validate id token: %s", err)
			}
			if idToken.Nonce != "something-nonce" {
				t.Errorf("nonce must be \"something-nonce\" but got %#v", idToken.Nonce)
			}

			if idToken.CodeHash != codeHash {
				t.Errorf("unexpected c_hash value:\nexpected: %s\n but got: %s", codeHash, idToken.CodeHash)
			}
			if idToken.AccessTokenHash != token.TokenHash(resp.AccessToken) {
				t.Errorf("unexpected at_hash value:\nexpected: %s\n but got: %s", token.TokenHash(resp.AccessToken), idToken.AccessTokenHash)
			}
		}
	}
}

func TestPostToken_Code(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	code, err := env.API.TokenManager.CreateCode(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"http://some-client.example.com/callback",
		"openid profile",
		"something-nonce",
		time.Now(),
		time.Duration(env.API.Config.Expire.Code),
	)
	if err != nil {
		t.Fatalf("failed to generate test code: %s", err)
	}

	codeWithoutOpenID, err := env.API.TokenManager.CreateCode(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"http://some-client.example.com/callback",
		"profile",
		"something-nonce",
		time.Now(),
		time.Duration(env.API.Config.Expire.Code),
	)
	if err != nil {
		t.Fatalf("failed to generate test code: %s", err)
	}

	invalidCode, err := env.API.TokenManager.CreateCode(
		&config.URL{Host: "another_issuer"},
		"macrat",
		"some_client_id",
		"http://some-client.example.com/callback",
		"openid profile",
		"",
		time.Now(),
		time.Duration(env.API.Config.Expire.Code),
	)
	if err != nil {
		t.Fatalf("failed to generate test code: %s", err)
	}

	env.JSONTest(t, "POST", "/token", []testutil.JSONTest{
		{
			Name: "missing code",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "code is required when use authorization_code grant type",
			},
		},
		{
			Name: "set refresh_token in authorization_code grant",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"refresh_token": {"some-token"},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "can't set refresh_token when use authorization_code grant type",
			},
		},
		{
			Name: "invlida code (can't parse)",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"invalid-code"},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_grant",
			},
		},
		{
			Name: "invlida code (invalid content)",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {invalidCode},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_grant",
			},
		},
		{
			Name: "missing client_id",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "client_id is required",
			},
		},
		{
			Name: "missing client_secret",
			Request: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {code},
				"client_id":    {"another_client_id"},
				"redirect_uri": {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "client_secret is required",
			},
		},
		{
			Name: "missing client_id in Basic authorization",
			Request: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {code},
				"redirect_uri": {"http://some-client.example.com/callback"},
			},
			Token: "Basic OnNlY3JldCBmb3Igc29tZS1jbGllbnQ=",
			Code:  http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "client_id is required",
			},
		},
		{
			Name: "missing client_secret in Basic authorization",
			Request: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {code},
				"redirect_uri": {"http://some-client.example.com/callback"},
			},
			Token: "Basic c29tZV9jbGllbnRfaWQ6",
			Code:  http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "client_secret is required",
			},
		},
		{
			Name: "not registered client_id",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"another_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_client",
			},
		},
		{
			Name: "incorrect client_secret",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"invalid secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_client",
			},
		},
		{
			Name: "missing redirect_uri",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "redirect_uri is required",
			},
		},
		{
			Name: "invalid redirect_uri",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"is not url::"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "redirect_uri is invalid format",
			},
		},
		{
			Name: "relative redirect_uri",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "redirect_uri is must be absolute URL",
			},
		},
		{
			Name: "non registered redirect_uri",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://another-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_grant",
			},
		},
		{
			Name: "success with query auth",
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code:      http.StatusOK,
			CheckBody: ResponseValidation(env, "openid profile", token.TokenHash(code)),
		},
		{
			Name: "success with basic auth",
			Request: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {code},
				"redirect_uri": {"http://some-client.example.com/callback"},
			},
			Token:     "Basic c29tZV9jbGllbnRfaWQ6c2VjcmV0IGZvciBzb21lLWNsaWVudA==",
			Code:      http.StatusOK,
			CheckBody: ResponseValidation(env, "openid profile", token.TokenHash(code)),
		},
		{
			Name: "success with basic auth / without openid scope",
			Request: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {codeWithoutOpenID},
				"redirect_uri": {"http://some-client.example.com/callback"},
			},
			Token:     "Basic c29tZV9jbGllbnRfaWQ6c2VjcmV0IGZvciBzb21lLWNsaWVudA==",
			Code:      http.StatusOK,
			CheckBody: ResponseValidation(env, "profile", token.TokenHash(code)),
		},
	})
}

func TestPostToken_RefreshToken(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	refreshToken, err := env.API.TokenManager.CreateRefreshToken(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"openid profile",
		"something-nonce",
		time.Now(),
		time.Duration(env.API.Config.Expire.Refresh),
	)
	if err != nil {
		t.Fatalf("failed to generate test refresh_token: %s", err)
	}

	refreshTokenWithoutOpenID, err := env.API.TokenManager.CreateRefreshToken(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"profile",
		"something-nonce",
		time.Now(),
		time.Duration(env.API.Config.Expire.Refresh),
	)
	if err != nil {
		t.Fatalf("failed to generate test refresh_token: %s", err)
	}

	invalidRefreshToken, err := env.API.TokenManager.CreateRefreshToken(
		&config.URL{Host: "another_issuer"},
		"macrat",
		"some_client_id",
		"openid profile",
		"",
		time.Now(),
		time.Duration(env.API.Config.Expire.Code),
	)
	if err != nil {
		t.Fatalf("failed to generate test refresh_token: %s", err)
	}

	env.JSONTest(t, "POST", "/token", []testutil.JSONTest{
		{
			Name: "missing refresh_token",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "refresh_token is required when use refresh_token grant type",
			},
		},
		{
			Name: "set code in refresh_token grant",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				"code":          {"some-code"},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "can't set code when use refresh_token grant type",
			},
		},
		{
			Name: "invalid refresh_token (can't parse)",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"invalid-token"},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_grant",
			},
		},
		{
			Name: "invalid refresh_token (invalid value)",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {invalidRefreshToken},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_grant",
			},
		},
		{
			Name: "missing client_id",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "client_id is required",
			},
		},
		{
			Name: "missing cilent_secret",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				"client_id":     {"some_client_id"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "client_secret is required",
			},
		},
		{
			Name: "not registered client_id",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				"client_id":     {"another_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_client",
			},
		},
		{
			Name: "incorrect client_secret",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				"client_id":     {"some_client_id"},
				"client_secret": {"invalid secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_client",
			},
		},
		{
			Name: "success",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code:      http.StatusOK,
			CheckBody: ResponseValidation(env, "openid profile", ""),
		},
		{
			Name: "success / without openid scope",
			Request: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshTokenWithoutOpenID},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code:      http.StatusOK,
			CheckBody: ResponseValidation(env, "profile", ""),
		},
	})
}
