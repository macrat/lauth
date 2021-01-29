package token

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"gopkg.in/square/go-jose.v2"
)

var (
	NotJWEError = errors.New("not a valid JWE data")
)

func (m Manager) encryptionKey() []byte {
	hash := sha256.Sum256(x509.MarshalPKCS1PrivateKey(m.private))
	return hash[:]
}

func (m Manager) encryptToken(token string) (string, error) {
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.A256GCMKW,
			Key:       m.encryptionKey(),
		},
		&jose.EncrypterOptions{
			Compression: jose.DEFLATE,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderContentType: "JWT",
			},
		},
	)
	if err != nil {
		return "", err
	}

	e, err := enc.Encrypt([]byte(token))
	if err != nil {
		return "", err
	}
	return e.CompactSerialize()
}

func (m Manager) decryptToken(token string) (string, error) {
	e, err := jose.ParseEncrypted(token)
	if err != nil {
		return "", err
	}

	if typ, ok := e.Header.ExtraHeaders[jose.HeaderContentType]; !ok || typ != "JWT" {
		return "", NotJWEError
	}

	dec, err := e.Decrypt(m.encryptionKey())
	if err != nil {
		return "", err
	}
	return string(dec), nil
}
