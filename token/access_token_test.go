package token_test

import (
	"testing"
	"time"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
	"github.com/macrat/lauth/token"
)

func TestAccessToken(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}

	accessToken, err := tokenManager.CreateAccessToken(issuer, "someone", "something", "openid profile", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}

	claims, err := tokenManager.ParseAccessToken(accessToken)
	if err != nil {
		t.Fatalf("failed to parse access token: %s", err)
	}

	if err = claims.Validate(issuer); err != nil {
		t.Errorf("failed to validate access token: %s", err)
	}

	if err = claims.Validate(&config.URL{Host: "another-issuer"}); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != token.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}

	idToken, _ := tokenManager.ParseIDToken(accessToken)
	if err = idToken.Validate(issuer, issuer.String()); err == nil {
		t.Fatalf("must be failed to validation access token as id token but success")
	} else if err != token.UnexpectedTokenTypeError {
		t.Errorf("unexpected error: %s", err)
	}
}
