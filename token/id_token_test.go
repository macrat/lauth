package token_test

import (
	"testing"
	"time"

	"github.com/macrat/ldapin/config"
	"github.com/macrat/ldapin/testutil"
	"github.com/macrat/ldapin/token"
)

func TestIDToken(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}
	audience := "something"

	idToken, err := tokenManager.CreateIDToken(issuer, "someone", audience, "", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}

	claims, err := tokenManager.ParseIDToken(idToken)
	if err != nil {
		t.Fatalf("failed to parse id_token: %s", err)
	}

	if err = claims.Validate(issuer, audience); err != nil {
		t.Errorf("failed to validate id_token: %s", err)
	}

	if err = claims.Validate(&config.URL{Host: "another-issuer"}, audience); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != token.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}

	if err = claims.Validate(issuer, "anotherone"); err == nil {
		t.Errorf("must be failed if audience is incorrect but success")
	} else if err != token.UnexpectedAudienceError {
		t.Errorf("unexpected error: %s", err)
	}

	idToken2, err := tokenManager.CreateIDToken(issuer, "someone", issuer.String(), "", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}

	code, _ := tokenManager.ParseCode(idToken2)
	if err = code.Validate(issuer); err == nil {
		t.Fatalf("must be failed to validation id_token as code but success")
	} else if err != token.UnexpectedTokenTypeError {
		t.Errorf("unexpected error: %s", err)
	}
}
