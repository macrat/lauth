package api_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/macrat/lauth/testutil"
	"github.com/rs/zerolog"
)

func init() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestErrorRoutes(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	resp := env.Get("/no/such/page", "", nil)
	if resp.Code != http.StatusNotFound {
		t.Errorf("expected status code 404 but got %d", resp.Code)
	} else if resp.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("unexpected content-type: %s", resp.Header().Get("Content-Type"))
	}

	req, _ := http.NewRequest("PATCH", "/authz", nil)
	resp = env.DoRequest(req)
	if resp.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status code 405 but got %d", resp.Code)
	} else if resp.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("unexpected content-type: %s", resp.Header().Get("Content-Type"))
	}

	req, _ = http.NewRequest("DELETE", "/token", nil)
	resp = env.DoRequest(req)
	if resp.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status code 405 but got %d", resp.Code)
	} else if resp.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("unexpected content-type: %s", resp.Header().Get("Content-Type"))
	}
}

func TestOpenIDConfiguration(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	stop := env.Start(t)
	defer stop()

	provider, err := oidc.NewProvider(context.TODO(), env.API.Config.Issuer.String())
	if err != nil {
		t.Fatalf("failed to get provider info: %s", err)
	}

	endpoints := provider.Endpoint()
	if endpoints.AuthURL != fmt.Sprintf("http://%s/authz", env.API.Config.Issuer.Host) {
		t.Errorf("unexpected authz endpoint guessed: %#v", endpoints.AuthURL)
	}
	if endpoints.TokenURL != fmt.Sprintf("http://%s/token", env.API.Config.Issuer.Host) {
		t.Errorf("unexpected token endpoint guessed: %#v", endpoints.TokenURL)
	}
}

func TestGetCerts(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	token, err := env.API.TokenManager.CreateAccessToken(env.API.Config.Issuer, "someone", "profile", time.Now(), 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate test token: %s", err)
	}

	stop := env.Start(t)
	defer stop()

	jwksURI := env.API.Config.OpenIDConfiguration().JwksEndpoint

	jwks := oidc.NewRemoteKeySet(context.TODO(), jwksURI)
	_, err = jwks.VerifySignature(context.TODO(), token)
	if err != nil {
		t.Errorf("failed verify signature using jwks key: %s", err)
	}
}
