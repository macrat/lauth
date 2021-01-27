package testutil

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/macrat/ldapin/token"
)

func MakeJWTManager() (token.JWTManager, error) {
	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return token.JWTManager{}, err
	}
	return token.NewJWTManager(pri)
}
