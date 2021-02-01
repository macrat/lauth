package api

import (
	"golang.org/x/crypto/bcrypt"
)

func CompareSecret(hash, secret string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
}
