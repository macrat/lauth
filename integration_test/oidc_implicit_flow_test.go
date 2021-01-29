package integration_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/macrat/ldapin/testutil"
)

func TestOIDCImplicitFlow(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)
	env.API.Config.AllowImplicitFlow = true

	clientID := "some_client_id"
	nonce := "This Is Nonce"

	resp := env.Post("/authz", "", url.Values{
		"response_type": {"token id_token"},
		"redirect_uri":  {"http://some-client.example.com/callback"},
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

	fragment, err := url.ParseQuery(location.Fragment)
	if err != nil {
		t.Fatalf("failed to parse fragment: %s", err)
	}

	if fragment.Get("id_token") == "" {
		t.Errorf("failed to get id_token")
	} else if idToken, err := env.API.TokenManager.ParseIDToken(fragment.Get("id_token")); err != nil {
		t.Errorf("failed to parse id_token: %s", err)
	} else if idToken.Nonce != nonce {
		t.Errorf("nonce of id_token expected %#v but got %#v", nonce, idToken.Nonce)
	}

	accessToken := fragment.Get("access_token")
	if accessToken == "" {
		t.Fatalf("failed to get access_token")
	}

	resp = env.Get("/userinfo", accessToken, nil)
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
