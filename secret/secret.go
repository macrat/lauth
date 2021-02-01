package secret

import (
	"crypto/rand"
	"crypto/sha512"

	"golang.org/x/crypto/bcrypt"
)

const (
	LENGTH = 100
)

var (
	CHAR_SET = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
)

func shash(secret []byte) []byte {
	h := sha512.Sum512(secret)
	return h[:]
}

func bhash(secret []byte) ([]byte, error) {
	b, err := bcrypt.GenerateFromPassword(secret, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func Hash(secret []byte) ([]byte, error) {
	return bhash(shash(secret))
}

func Compare(hash, secret string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), shash([]byte(secret)))
}

func generatePlainSecret() ([]byte, error) {
	b := make([]byte, LENGTH)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	for i := range b {
		b[i] = CHAR_SET[int(b[i])%len(CHAR_SET)]
	}

	return b, nil
}

type GeneratedSecret struct {
	Secret []byte
	Hash   []byte
}

func Generate() (GeneratedSecret, error) {
	secret, err := generatePlainSecret()
	if err != nil {
		return GeneratedSecret{}, err
	}

	h, err := Hash(secret)
	if err != nil {
		return GeneratedSecret{}, err
	}

	return GeneratedSecret{
		Secret: secret,
		Hash:   h,
	}, nil
}
