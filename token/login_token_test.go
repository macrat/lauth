package token_test

import (
	"testing"
	"time"

	"github.com/macrat/ldapin/config"
	"github.com/macrat/ldapin/testutil"
	"github.com/macrat/ldapin/token"
)

func TestLoginToken(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}

	loginToken, err := tokenManager.CreateLoginToken(issuer, "someone", "something", 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}

	claims, err := tokenManager.ParseLoginToken(loginToken)
	if err != nil {
		t.Fatalf("failed to parse login token: %s", err)
	}

	if err = claims.Validate(issuer); err != nil {
		t.Errorf("failed to validate login token: %s", err)
	}

	if err = claims.Validate(&config.URL{Host: "another-issuer"}); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != token.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}

	idToken, _ := tokenManager.ParseIDToken(loginToken)
	if err = idToken.Validate(issuer, issuer.String()); err == nil {
		t.Fatalf("must be failed to validation login token as id token but success")
	} else if err != token.UnexpectedTokenTypeError {
		t.Errorf("unexpected error: %s", err)
	}
}