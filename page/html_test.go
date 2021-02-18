package page_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/macrat/lauth/testutil"
)

func TestLoginForm_value_passing(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"some_client_id"},
		"redirect_uri":  {"http://some-client.example.com/callback"},
		"scope":         {"openid profile"},
		"state":         {"this-is-state"},
		"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
			"iss":     "some_client_id",
			"aud":     env.API.Config.Issuer.String(),
			"max_age": 123,
			"nonce":   "noncenoncenonce",
		})},
	}
	resp := env.Get("/authz", "", params)

	if resp.Code != http.StatusOK {
		t.Log(string(resp.Body.Bytes()))
		t.Fatalf("failed to render login page (status code = %d)", resp.Code)
	}

	inputs, err := testutil.FindInputsByHTML(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse login page: %s", err)
	}

	if request, ok := inputs["request"]; !ok {
		t.Errorf("request is missing in form")
	} else if claims, err := env.API.TokenManager.ParseRequestObject(request, ""); err != nil {
		t.Errorf("failed to parse request object: %s", err)
	} else if err = claims.Validate(env.API.Config.Issuer.String(), env.API.Config.Issuer); err != nil {
		t.Errorf("failed to validate request object: %s", err)
	} else {
		if claims.ResponseType != "code" {
			t.Errorf("unexpected response_type in request object: %#v", claims.RedirectURI)
		}
		if claims.RedirectURI != "http://some-client.example.com/callback" {
			t.Errorf("unexpected redirect_uri in request object: %#v", claims.RedirectURI)
		}
		if claims.Scope != "openid profile" {
			t.Errorf("unexpected scope in request object: %#v", claims.Scope)
		}
		if claims.State != "this-is-state" {
			t.Errorf("unexpected state in request object: %#v", claims.State)
		}
		if claims.MaxAge != 123 {
			t.Errorf("unexpected max_age in request object: %#v", claims.MaxAge)
		}
		if claims.Nonce != "noncenoncenonce" {
			t.Errorf("unexpected nonce in request object: %#v", claims.Nonce)
		}
	}

	if _, ok := inputs["username"]; !ok {
		t.Errorf("username is missing in form")
	}

	if _, ok := inputs["password"]; !ok {
		t.Errorf("password is missing in form")
	}
}
