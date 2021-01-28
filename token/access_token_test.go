package token_test

import (
	"testing"
	"time"

	"github.com/macrat/ldapin/config"
	"github.com/macrat/ldapin/testutil"
	"github.com/macrat/ldapin/token"
)

func TestAccessToken(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}

	accessToken, err := tokenManager.CreateAccessToken(issuer, "someone", "openid profile", time.Now(), 10*time.Minute)
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

	code, _ := tokenManager.ParseCode(accessToken)
	if err = code.Validate(issuer); err == nil {
		t.Fatalf("must be failed to validation access token as code but success")
	} else if err != token.UnexpectedTokenTypeError {
		t.Errorf("unexpected error: %s", err)
	}
}
