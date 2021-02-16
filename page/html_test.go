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
		"nonce":         {"noncenoncenonce"},
		"max_age":       {"123"},
		"request": {testutil.SomeClientRequestObject(t, map[string]interface{}{
			"iss": "some_client_id",
			"aud": env.API.Config.Issuer.String(),
		})},
	}
	resp := env.Get("/authz", "", params)

	if resp.Code != http.StatusOK {
		t.Fatalf("failed to render login page (status code = %d)", resp.Code)
	}

	inputs, err := testutil.FindInputsByHTML(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse login page: %s", err)
	}

	for key := range params {
		if v, ok := inputs[key]; !ok {
			t.Errorf("parameter %s is missing in form", key)
		} else if params.Get(key) != v {
			t.Errorf("parameter %s is expected %s but got %s", key, params.Get(key), v)
		}
	}

	if _, ok := inputs["username"]; !ok {
		t.Errorf("username is missing in form")
	}

	if _, ok := inputs["password"]; !ok {
		t.Errorf("password is missing in form")
	}

	if _, ok := inputs["session"]; !ok {
		t.Errorf("session is missing in form")
	}
}
