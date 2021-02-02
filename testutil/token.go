package testutil

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/macrat/lauth/token"
)

func MakeTokenManager() (token.Manager, error) {
	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return token.Manager{}, err
	}
	return token.NewManager(pri)
}
