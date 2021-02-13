package api_test

import (
	"testing"
	"time"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/testutil"
)

func TestMakeAndTestLoginSession(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	correctSession, err := env.API.MakeLoginSession("10.1.2.3", "some_client_id")
	if err != nil {
		t.Fatalf("failed to generate login session: %s", err)
	}

	expireBackup := env.API.Config.Expire.Login
	env.API.Config.Expire.Login = config.Duration(-10 * time.Minute)
	expiredSession, err := env.API.MakeLoginSession("10.1.2.3", "some_client_id")
	if err != nil {
		t.Fatalf("failed to generate login session: %s", err)
	}
	env.API.Config.Expire.Login = expireBackup

	env2 := testutil.NewAPITestEnvironment(t)
	anotherIssuerSession, err := env2.API.MakeLoginSession("10.1.2.3", "some_client_id")
	if err != nil {
		t.Fatalf("failed to generate login session: %s", err)
	}

	tests := []struct {
		Name     string
		Token    string
		UserIP   string
		ClientID string
		Result   bool
	}{
		{
			Name:     "success",
			Token:    correctSession,
			UserIP:   "10.1.2.3",
			ClientID: "some_client_id",
			Result:   true,
		},
		{
			Name:     "incorrect user IP",
			Token:    correctSession,
			UserIP:   "10.0.0.0",
			ClientID: "some_client_id",
			Result:   false,
		},
		{
			Name:     "incorrect client ID",
			Token:    correctSession,
			UserIP:   "10.1.2.3",
			ClientID: "another_client_id",
			Result:   false,
		},
		{
			Name:     "expired",
			Token:    expiredSession,
			UserIP:   "10.1.2.3",
			ClientID: "some_client_id",
			Result:   false,
		},
		{
			Name:     "can't parse",
			Token:    "invalid token",
			UserIP:   "10.1.2.3",
			ClientID: "some_client_id",
			Result:   false,
		},
		{
			Name:     "another issuer",
			Token:    anotherIssuerSession,
			UserIP:   "10.1.2.3",
			ClientID: "some_client_id",
			Result:   false,
		},
	}

	for _, tt := range tests {
		if got := env.API.IsValidLoginSession(tt.Token, tt.UserIP, tt.ClientID); got != tt.Result {
			t.Errorf("%s: expected %t but got %t", tt.Name, tt.Result, got)
		}
	}
}
