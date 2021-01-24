package main_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestOIDCAuthzCodeFlow(t *testing.T) {
	env := NewAPITestEnvironment(t)

	clientID := "hello_client"
	nonce := "this is Nonce"

	resp := env.Post("/authn", "", url.Values{
		"response_type": {"code"},
		"redirect_uri":  {"http://localhost:3000"},
		"client_id":     {clientID},
		"nonce":         {nonce},
		"scope":         {"phone"},
		"username":      {"macrat"},
		"password":      {"foobar"},
	})

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

	resp = env.Post("/token", "", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
	})

	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.Code)
	}

	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err = json.Unmarshal(resp.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("failed to parse body: %s", err)
	}

	if idToken, err := env.API.JWTManager.ParseIDToken(tokens.IDToken); err != nil {
		t.Errorf("failed to parse id_token: %s", err)
	} else if idToken.Nonce != nonce {
		t.Errorf("nonce of id_token expected %#v but got %#v", nonce, idToken.Nonce)
	}

	resp = env.Get("/userinfo", tokens.AccessToken, nil)
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
