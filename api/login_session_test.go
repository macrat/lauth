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
		Error    string
	}{
		{
			Name:     "success",
			Token:    correctSession,
			UserIP:   "10.1.2.3",
			ClientID: "some_client_id",
			Error:    "",
		},
		{
			Name:     "incorrect user IP",
			Token:    correctSession,
			UserIP:   "10.0.0.0",
			ClientID: "some_client_id",
			Error:    "mismatch User IP",
		},
		{
			Name:     "incorrect client ID",
			Token:    correctSession,
			UserIP:   "10.1.2.3",
			ClientID: "another_client_id",
			Error:    "mismatch Client ID",
		},
		{
			Name:     "expired",
			Token:    expiredSession,
			UserIP:   "10.1.2.3",
			ClientID: "some_client_id",
			Error:    "token is expired by 10m0s",
		},
		{
			Name:     "can't parse",
			Token:    "invalid token",
			UserIP:   "10.1.2.3",
			ClientID: "some_client_id",
			Error:    "token contains an invalid number of segments",
		},
		{
			Name:     "another issuer",
			Token:    anotherIssuerSession,
			UserIP:   "10.1.2.3",
			ClientID: "some_client_id",
			Error:    "crypto/rsa: verification error",
		},
	}

	for _, tt := range tests {
		err := env.API.ValidateLoginSession(tt.Token, tt.UserIP, tt.ClientID)

		if tt.Error == "" && err != nil {
			t.Errorf("%s: expected valid but got %s", tt.Name, err)
		}
		if tt.Error != "" {
			if err == nil {
				t.Errorf("%s: expected not valid but reports as valid", tt.Name)
			} else if err.Error() != tt.Error {
				t.Errorf("%s: expected error %#v but got %#v", tt.Name, tt.Error, err.Error())
			}
		}
	}
}
