package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"time"
)

type JWK struct {
	KeyID     string   `json:"kid"`
	Use       string   `json:"use"`
	Algorithm string   `json:"alg"`
	KeyType   string   `json:"kty"`
	E         string   `json:"e"`
	N         string   `json:"n"`
	X509      []string `json:"x5c"`
}

func int2bytes(i int) []byte {
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(i))
	skip := 0
	for skip < 8 && bs[skip] == 0x00 {
		skip++
	}
	return bs[skip:]
}

func makeCert(hostname string, public *rsa.PublicKey, private *rsa.PrivateKey) ([]byte, error) {
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: hostname},
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}

	b, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (m Manager) JWKs(hostname string) ([]JWK, error) {
	cert, err := makeCert(hostname, m.public, m.private)
	if err != nil {
		return nil, err
	}

	return []JWK{
		{
			KeyID:     m.KeyID().String(),
			Use:       "sig",
			Algorithm: "RS256",
			KeyType:   "RSA",
			E:         base64.RawURLEncoding.EncodeToString(int2bytes(m.public.E)),
			N:         base64.RawURLEncoding.EncodeToString(m.public.N.Bytes()),
			X509: []string{
				base64.StdEncoding.EncodeToString(cert),
			},
		},
	}, nil
}
