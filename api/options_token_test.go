package api_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/macrat/lauth/testutil"
)

func TestOptionsToken(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	req, err := http.NewRequest("OPTIONS", "/token", nil)
	if err != nil {
		t.Fatalf("failed to make request: %s", err)
	}

	resp := env.DoRequest(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("failed to fetch token endpoint with OPTIONS method: %d", resp.Code)
	}

	req.Header.Set("Origin", "http://implicit-client.example.com")
	resp = env.DoRequest(req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 forbidden if set Origin header but got %d", resp.Code)
	}

	expected := map[string]string{
		"error":             "access_denied",
		"error_description": "Origin header was set. You can't use token endpoint via browser.",
	}

	var body map[string]string
	if err = json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Errorf("failed to parse response body: %s", err)
	} else if !reflect.DeepEqual(body, expected) {
		t.Errorf("unexpected response: %#v", string(resp.Body.Bytes()))
	}
}
