package token_test

import (
	"testing"
	"time"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
	"github.com/macrat/lauth/token"
)

func TestRefreshToken(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}

	refreshToken, err := tokenManager.CreateRefreshToken(issuer, "someone", "something", "email profile", "this-is-nonce", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}

	claims, err := tokenManager.ParseRefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("failed to parse refresh_token: %s", err)
	}

	if err = claims.Validate(issuer); err != nil {
		t.Errorf("failed to validate refresh_token: %s", err)
	}

	if err = claims.Validate(&config.URL{Host: "another-issuer"}); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != token.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}
}
