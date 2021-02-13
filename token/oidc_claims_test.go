package token_test

import (
	"testing"
	"time"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/token"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

func TestOIDCCLaims_Validate(t *testing.T) {
	tests := []struct {
		Name     string
		Claims   token.OIDCClaims
		Issuer   *config.URL
		Audience string
		Error    string
	}{
		{
			Name: "success",
			Claims: token.OIDCClaims{
				StandardClaims: jwt.StandardClaims{
					Issuer:    "https://example.com",
					Subject:   "someone",
					Audience:  "something",
					ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
				},
			},
			Issuer:   &config.URL{Scheme: "https", Host: "example.com"},
			Audience: "something",
			Error:    "",
		},
		{
			Name: "incorrect issuer",
			Claims: token.OIDCClaims{
				StandardClaims: jwt.StandardClaims{
					Issuer:    "https://example.com",
					Subject:   "someone",
					Audience:  "something",
					ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
				},
			},
			Issuer:   &config.URL{Scheme: "https", Host: "invalid.example.com"},
			Audience: "something",
			Error:    "unexpected issuer",
		},
		{
			Name: "incorrect audience",
			Claims: token.OIDCClaims{
				StandardClaims: jwt.StandardClaims{
					Issuer:    "https://example.com",
					Subject:   "someone",
					Audience:  "something",
					ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
				},
			},
			Issuer:   &config.URL{Scheme: "https", Host: "example.com"},
			Audience: "another",
			Error:    "unexpected audience",
		},
		{
			Name: "expired",
			Claims: token.OIDCClaims{
				StandardClaims: jwt.StandardClaims{
					Issuer:    "https://example.com",
					Subject:   "someone",
					Audience:  "something",
					ExpiresAt: time.Now().Add(-5 * time.Minute).Unix(),
				},
			},
			Issuer:   &config.URL{Scheme: "https", Host: "example.com"},
			Audience: "something",
			Error:    "token is expired by 5m0s",
		},
	}

	for _, tt := range tests {
		err := tt.Claims.Validate(tt.Issuer, tt.Audience)

		if tt.Error == "" && err != nil {
			t.Errorf("%s: unexpected error: %s", tt.Name, err)
		}
		if tt.Error != "" && err.Error() != tt.Error {
			t.Errorf("%s: unexpected error:\nexpected: %s\nbut got: %s", tt.Name, tt.Error, err)
		}
	}
}
