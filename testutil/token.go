package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/macrat/lauth/token"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

var (
	SomeClientPublicKey = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALbggP+d69CABfnZ+8B3Kzxwy+rlpRP3
nvOgtLi3SYCfjLAPABz4Nm3ReQZosXHrPnOXcaL6+vydBkD4bUyiAOcCAwEAAQ==
-----END PUBLIC KEY-----`
	SomeClientPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALbggP+d69CABfnZ+8B3Kzxwy+rlpRP3nvOgtLi3SYCfjLAPABz4
Nm3ReQZosXHrPnOXcaL6+vydBkD4bUyiAOcCAwEAAQJAV+BhnHNCUZpzRLBerQmW
mSCKnIFlZcbjdqaOsQRCKa+xFwwyHXB0Pa0U9VSmRojNnQHYT2TiPiF+owMKgbDD
gQIhAOWdbe8hbfykzM49YVRIxVYfUe6MXHjbFRWLZlVNQLBRAiEAy+QvgqVZ5Jul
ux8NtTBPIwnpUWS+8jjpjDKU8VzFx7cCIEbuI+isBgL2kcHgGjHkLPmWwUOUnnhD
DTdTkbAmJiaRAiEAkgmd0gjXSzwEx/NlIRs6A5HM0STE87+54FY2gm59px8CIEn+
acMOpeucfTwPuDLEdNm3Hfpldkgujdd3uaEzAjzI
-----END RSA PRIVATE KEY-----`

	ImplicitClientPublicKey = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALDdxc6RXRv6kityrC47SHRp1/Zk0Sao
soXm3hlRCEdCrCDo9vVXzE85pEAn3MfSJeRBIxN+QCJn+UQE5Ph+kIcCAwEAAQ==
-----END PUBLIC KEY-----`
	ImplicitClientPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALDdxc6RXRv6kityrC47SHRp1/Zk0SaosoXm3hlRCEdCrCDo9vVX
zE85pEAn3MfSJeRBIxN+QCJn+UQE5Ph+kIcCAwEAAQJAeBBEvKKva1PhMD9rJQM3
f1dutKPh23V/oyiDMvpwPTaiOmXEpofxKdAklR2mKetZpma+NHFvImZKE2SmUJ/y
eQIhAOoz0HiDmuSXOq6B0H+Z2vDVsvPZrLUtuFb+0/fcCVr9AiEAwVPZWMITOGrg
P1DNaRH9yuYCQtdI/1Alqu0tDK7cetMCIQDJ/l5zUq6pMXW/RN9a7ovS470wbDF1
IjW3cpnHUNQQ0QIgIGzf13M1phDG69exnB3YY1+QoYVaSPg4WSLOm4H4mOECIGdI
WtTXDjshzLGGhgZ76v3/5oHfFhc7AEpl75tsM3iD
-----END RSA PRIVATE KEY-----`
)

func MakeTokenManager() (token.Manager, error) {
	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return token.Manager{}, err
	}
	return token.NewManager(pri)
}

func MakeRequestObject(t *testing.T, values map[string]interface{}, key string) string {
	pri, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key))
	if err != nil {
		t.Fatalf("failed to prepare key for signing to request object: %s", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(values))
	result, err := token.SignedString(pri)
	if err != nil {
		t.Errorf("failed to signing to request object: %s", err)
	}
	return result
}

func SomeClientRequestObject(t *testing.T, values map[string]interface{}) string {
	return MakeRequestObject(t, values, SomeClientPrivateKey)
}

func ImplicitClientRequestObject(t *testing.T, values map[string]interface{}) string {
	return MakeRequestObject(t, values, ImplicitClientPrivateKey)
}
