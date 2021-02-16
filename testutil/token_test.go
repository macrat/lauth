package testutil_test

import (
	"testing"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
)

func TestMakeRequestObject(t *testing.T) {
	m, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to prepare token manager: %s", err)
	}

	req := testutil.SomeClientRequestObject(t, map[string]interface{}{
		"iss": "some_client_id",
		"aud": "https://example.com",
	})

	claims, err := m.ParseRequestObject(req, testutil.SomeClientPublicKey)
	if err != nil {
		t.Fatalf("failed to parse request object: %s", err)
	}

	err = claims.Validate(&config.URL{Scheme: "https", Host: "example.com"}, "some_client_id")
	if err != nil {
		t.Fatalf("failed to parse validate request object: %s", err)
	}
}
