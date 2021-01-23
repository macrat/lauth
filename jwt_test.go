package main_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/macrat/ldapin"
)

func makeJWTManager() (main.JWTManager, error) {
	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return main.JWTManager{}, err
	}
	return main.NewJWTManager(pri)
}

func TestCodeToken(t *testing.T) {
	jwtManager, err := makeJWTManager()
	if err != nil {
		t.Fatalf("failed to generate JWTManager: %s", err)
	}

	issuer := "http://localhost:8000"

	code, err := jwtManager.CreateCode(issuer, "someone", "something", "openid profile", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %s", err)
	}

	claims, err := jwtManager.ParseCode(code)
	if err != nil {
		t.Fatalf("failed to parse code: %s", err)
	}

	if err = claims.Validate(issuer); err != nil {
		t.Errorf("failed to validate code: %s", err)
	}

	if err = claims.Validate("another-issuer"); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != main.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}

	accessToken, _ := jwtManager.ParseAccessToken(code)
	if err = accessToken.Validate(issuer); err == nil {
		t.Fatalf("must be failed to validation code as access token but success")
	} else if err != main.UnexpectedTokenTypeError {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestAccessToken(t *testing.T) {
	jwtManager, err := makeJWTManager()
	if err != nil {
		t.Fatalf("failed to generate JWTManager: %s", err)
	}

	issuer := "http://localhost:8000"

	token, err := jwtManager.CreateAccessToken(issuer, "someone", "openid profile", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}

	claims, err := jwtManager.ParseAccessToken(token)
	if err != nil {
		t.Fatalf("failed to parse access token: %s", err)
	}

	if err = claims.Validate(issuer); err != nil {
		t.Errorf("failed to validate access token: %s", err)
	}

	if err = claims.Validate("another-issuer"); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != main.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}

	code, _ := jwtManager.ParseCode(token)
	if err = code.Validate(issuer); err == nil {
		t.Fatalf("must be failed to validation access token as code but success")
	} else if err != main.UnexpectedTokenTypeError {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestIDToken(t *testing.T) {
	jwtManager, err := makeJWTManager()
	if err != nil {
		t.Fatalf("failed to generate JWTManager: %s", err)
	}

	issuer := "http://localhost:8000"

	_, err = jwtManager.CreateIDToken(issuer, "someone", "something", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}
}
