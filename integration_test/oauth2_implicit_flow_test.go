package integration_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/macrat/lauth/testutil"
)

func TestOAuth2ImplicitFlow(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	clientID := "implicit_client_id"

	resp := env.Get("/authz", "", url.Values{
		"response_type": {"token"},
		"redirect_uri":  {"http://implicit-client.example.com/callback"},
		"client_id":     {clientID},
		"scope":         {"phone"},
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.Code)
	}
	request, err := testutil.FindRequestObjectByHTML(resp.Body)
	if err != nil {
		t.Fatalf("failed to get request object: %s", err)
	}

	resp = env.Post("/authz", "", url.Values{
		"client_id":     {clientID},
		"response_type": {"token"},
		"request":       {request},
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

	accessToken := fragment.Get("access_token")
	if accessToken == "" {
		t.Fatalf("failed to get access_token")
	}

	resp = env.Get("/userinfo", "Bearer "+accessToken, nil)
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
