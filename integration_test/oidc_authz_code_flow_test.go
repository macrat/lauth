package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/macrat/lauth/testutil"
	"golang.org/x/oauth2"
)

func TestOIDCAuthzCodeFlow(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	stop := env.Start(t)
	defer stop()

	provider, err := oidc.NewProvider(context.TODO(), env.API.Config.Issuer.String())
	if err != nil {
		t.Fatalf("failed to get provider info: %s", err)
	}

	clientID := "some_client_id"
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	oauth2config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: "secret for some-client",
		RedirectURL:  "http://some-client.example.com/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "phone"},
	}

	authURL, err := url.Parse(oauth2config.AuthCodeURL("this is state"))
	if err != nil {
		t.Fatalf("failed to mage auth code URL: %s", err)
	}

	authQuery := authURL.Query()
	authQuery.Set("username", "macrat")
	authQuery.Set("password", "foobar")

	session, err := env.API.MakeLoginSession("::1", "some_client_id")
	if err != nil {
		t.Fatalf("failed to create login session: %s", err)
	}
	authQuery.Set("session", session)

	resp := env.Post("/authz", "", authQuery)

	if resp.Code != http.StatusFound {
		t.Fatalf("unexpected status code: %d", resp.Code)
	}
	location, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse location: %s", err)
	}

	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("failed to get code")
	}

	oauth2token, err := oauth2config.Exchange(context.TODO(), code)
	if err != nil {
		t.Fatalf("failed to exchange token: %s", err)
	}
	if !oauth2token.Valid() {
		t.Errorf("access_token is not valid")
	}

	if rawIDToken, ok := oauth2token.Extra("id_token").(string); !ok {
		t.Errorf("failed to get id_token")
	} else if idToken, err := verifier.Verify(context.TODO(), rawIDToken); err != nil {
		t.Errorf("failed to verify id_token: %s", err)
	} else {
		var claims struct {
			Subject string `json:"sub"`
		}
		if err = idToken.Claims(&claims); err != nil {
			t.Errorf("failed to parse id_token: %s", err)
		} else if claims.Subject != "macrat" {
			t.Errorf("unexpected id_token subject: %s", claims.Subject)
		}
	}

	req, _ := http.NewRequest("GET", "http://localhost:38980/userinfo", nil)
	oauth2token.SetAuthHeader(req)
	resp = env.DoRequest(req)

	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.Code)
	}

	var userinfo map[string]interface{}
	if err = json.Unmarshal(resp.Body.Bytes(), &userinfo); err != nil {
		t.Fatalf("failed to parse body: %s", err)
	}

	if !reflect.DeepEqual(userinfo, map[string]interface{}{
		"sub":          "macrat",
		"phone_number": "000-1234-5678",
	}) {
		t.Errorf("unexpected response body: %s", string(resp.Body.Bytes()))
	}
}
