package token_test

import (
	"testing"
	"time"

	"github.com/macrat/ldapin/config"
	"github.com/macrat/ldapin/testutil"
	"github.com/macrat/ldapin/token"
)

func TestCodeToken(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}

	code, err := tokenManager.CreateCode(issuer, "someone", "something", "http://something", "openid profile", "", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %s", err)
	}

	claims, err := tokenManager.ParseCode(code)
	if err != nil {
		t.Fatalf("failed to parse code: %s", err)
	}

	if err = claims.Validate(issuer); err != nil {
		t.Errorf("failed to validate code: %s", err)
	}

	if err = claims.Validate(&config.URL{Host: "another-issuer"}); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != token.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}
}
