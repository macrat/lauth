package api_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/coreos/go-oidc"
	"github.com/macrat/ldapin/testutil"
)

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
