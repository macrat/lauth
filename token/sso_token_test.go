package token_test

import (
	"testing"
	"time"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
	"github.com/macrat/lauth/token"
)

func TestAuthorizedParties(t *testing.T) {
	azp := token.AuthorizedParties{"some_client_id", "implicit_client_id"}

	if !azp.Includes("some_client_id") {
		t.Errorf("expected some_client_id is includes but reports as not")
	}

	if azp.Includes("another_client_id") {
		t.Errorf("expected another_client_id is not includes but reports as includes")
	}

	azp = azp.Append("some_client_id")
	if len(azp) != 2 {
		t.Errorf("expected azp length still 2 but got %d", len(azp))
	}

	azp = azp.Append("another_client_id")
	if len(azp) != 3 {
		t.Errorf("expected azp length now 3 but got %d", len(azp))
	}

	if !azp.Includes("another_client_id") {
		t.Errorf("expected another_client_id is now includes but reports as not")
	}
}

func TestSSOToken(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}

	ssoToken, err := tokenManager.CreateSSOToken(
		issuer,
		"someone",
		token.AuthorizedParties{"some_client_id"},
		time.Now(),
		time.Now().Add(10*time.Minute),
	)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}

	claims, err := tokenManager.ParseSSOToken(ssoToken)
	if err != nil {
		t.Fatalf("failed to parse token: %s", err)
	}

	if err = claims.Validate(issuer); err != nil {
		t.Errorf("failed to validate token: %s", err)
	}

	if err = claims.Validate(&config.URL{Host: "another-issuer"}); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != token.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}
}
