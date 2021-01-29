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

	code, err := env.API.TokenManager.CreateCode(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"http://some-client.example.com/callback",
		"openid profile",
		"something-nonce",
		time.Now(),
		time.Duration(env.API.Config.TTL.Code),
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
		time.Duration(env.API.Config.TTL.Code),
	)
	if err != nil {
		t.Fatalf("failed to generate test code: %s", err)
	}

	env.JSONTest(t, "POST", "/token", []testutil.JSONTest{
		{
			Request: url.Values{
				"grant_type":    {"invalid_grant_type"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "unsupported_grant_type",
				"error_description": "only supported grant_type is authorization_code",
			},
		},
		{
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "code is required",
			},
		},
		{
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
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"another_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "unauthorized_client",
			},
		},
		{
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"invalid secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "unauthorized_client",
			},
		},
		{
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
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://another-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "redirect_uri is miss match",
			},
		},
		{
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
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

				accessToken, err := env.API.TokenManager.ParseAccessToken(resp.AccessToken)
				if err != nil {
					t.Errorf("failed to parse access token: %s", err)
				}
				if err = accessToken.Validate(env.API.Config.Issuer); err != nil {
					t.Errorf("failed to validate access token: %s", err)
				}

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
			},
		},
	})
}

func TestPostToken_PublicClients(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)
	env.API.Config.DisableClientAuth = true

	code, err := env.API.TokenManager.CreateCode(
		env.API.Config.Issuer,
		"macrat",
		"some_client_id",
		"http://some-client.example.com/callback",
		"openid profile",
		"something-nonce",
		time.Now(),
		time.Duration(env.API.Config.TTL.Code),
	)
	if err != nil {
		t.Fatalf("failed to generate test code: %s", err)
	}

	env.JSONTest(t, "POST", "/token", []testutil.JSONTest{
		{
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "client_id is required if set client_secret",
			},
		},
		{
			Request: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {"some_client_id"},
				"client_secret": {"secret for some-client"},
				"redirect_uri":  {"http://some-client.example.com/callback"},
			},
			Code: http.StatusOK,
			CheckBody: func(t *testing.T, body testutil.RawBody) {
			},
		},
		{
			Request: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {code},
				"client_id":    {"some_client_id"},
				"redirect_uri": {"http://some-client.example.com/callback"},
			},
			Code: http.StatusOK,
			CheckBody: func(t *testing.T, body testutil.RawBody) {
			},
		},
		{
			Request: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {code},
				"client_id":    {"another_client_id"},
				"redirect_uri": {"http://some-client.example.com/callback"},
			},
			Code: http.StatusBadRequest,
			Body: map[string]interface{}{
				"error": "invalid_grant",
			},
		},
		{
			Request: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {code},
				"redirect_uri": {"http://some-client.example.com/callback"},
			},
			Code: http.StatusOK,
			CheckBody: func(t *testing.T, body testutil.RawBody) {
			},
		},
	})
}
