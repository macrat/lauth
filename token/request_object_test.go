package token_test

import (
	"testing"
	"time"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
	"github.com/macrat/lauth/token"
)

func TestRequestToken(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}

	request := testutil.SomeClientRequestObject(t, map[string]interface{}{
		"iss":          "some_client_id",
		"aud":          issuer.String(),
		"redirect_uri": "http://some-client.example.com/callback",
		"state":        "hello world",
	})

	if _, err := tokenManager.ParseRequestObject(request, "implicit_client_id", testutil.ImplicitClientPublicKey); err == nil {
		t.Errorf("expected failure if parse request as another client but success")
	}
	if _, err := tokenManager.ParseRequestObject(request, "implicit_client_id", testutil.SomeClientPublicKey); err == nil {
		t.Errorf("expected failure if parse request with another client ID")
	}
	if _, err := tokenManager.ParseRequestObject(request, "some_client_id", testutil.ImplicitClientPublicKey); err == nil {
		t.Errorf("expected failure if parse request with another cilent key")
	}

	claims, err := tokenManager.ParseRequestObject(request, "some_client_id", testutil.SomeClientPublicKey)
	if err != nil {
		t.Fatalf("failed to parse request object: %s", err)
	}

	if err = claims.Validate("some_client_id", issuer); err != nil {
		t.Errorf("failed to validate request object: %s", err)
	}

	if err = claims.Validate("some_client_id", &config.URL{Host: "another-issuer"}); err == nil {
		t.Errorf("must be failed if provider is incorrect but success")
	} else if err != token.UnexpectedAudienceError {
		t.Errorf("unexpected error: %s", err)
	}

	if err = claims.Validate("another_client_id", issuer); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != token.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}

	if claims.RedirectURI != "http://some-client.example.com/callback" {
		t.Errorf("unexpected redirect_uri value: %#v", claims.RedirectURI)
	}

	if claims.State != "hello world" {
		t.Errorf("unexpected state value: %#v", claims.State)
	}
}

func TestRequestToken_SelfIssue(t *testing.T) {
	tokenManager, err := testutil.MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to generate TokenManager: %s", err)
	}

	issuer := &config.URL{Scheme: "http", Host: "localhost:8000"}

	request, err := tokenManager.CreateRequestObject(issuer, "::1", token.RequestObjectClaims{
		ClientID: "something",
		Nonce:    "hello world",
	}, time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("failed to generate request object: %s", err)
	}

	claims, err := tokenManager.ParseRequestObject(request, "", "")
	if err != nil {
		t.Fatalf("failed to parse request object: %s", err)
	}

	if err = claims.Validate("some_client_id", issuer); err != nil {
		t.Errorf("failed to validate request object: %s", err)
	}

	if err = claims.Validate("some_client_id", &config.URL{Host: "another-issuer"}); err == nil {
		t.Errorf("must be failed if provider is incorrect but success")
	} else if err != token.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}

	if claims.ClientID != "something" {
		t.Errorf("unexpected client_id value: %#v", claims.Nonce)
	}

	if claims.Nonce != "hello world" {
		t.Errorf("unexpected nonce value: %#v", claims.Nonce)
	}
}
