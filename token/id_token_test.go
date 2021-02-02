package token_test

import (
	"testing"
	"time"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
	"github.com/macrat/lauth/token"
)

func TestIDToken(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}
	audience := "something"

	idToken, err := tokenManager.CreateIDToken(issuer, "someone", audience, "", "code", "token", nil, time.Now(), 10*time.Minute)
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

	if claims.CodeHash != token.TokenHash("code") {
		t.Errorf("unexpected c_hash: %s", claims.CodeHash)
	}

	if claims.AccessTokenHash != token.TokenHash("token") {
		t.Errorf("unexpected at_hash: %s", claims.AccessTokenHash)
	}

	idToken2, err := tokenManager.CreateIDToken(issuer, "someone", issuer.String(), "", "", "", nil, time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}

	accessToken, _ := tokenManager.ParseAccessToken(idToken2)
	if err = accessToken.Validate(issuer); err == nil {
		t.Fatalf("must be failed to validation id_token as access_token but success")
	} else if err != token.UnexpectedTokenTypeError {
		t.Errorf("unexpected error: %s", err)
	}

	claims2, err := tokenManager.ParseIDToken(idToken2)
	if err != nil {
		t.Fatalf("failed to parse id_token: %s", err)
	}
	if claims2.CodeHash != "" {
		t.Errorf("unexpected c_hash: %s", claims2.CodeHash)
	}
	if claims2.AccessTokenHash != "" {
		t.Errorf("unexpected at_hash: %s", claims2.AccessTokenHash)
	}
}
