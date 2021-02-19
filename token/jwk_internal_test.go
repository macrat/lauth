package token

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestInt2bytes(t *testing.T) {
	tests := []struct {
		Input  int
		Expect []byte
	}{
		{0, []byte{}},
		{0x1234, []byte{0x12, 0x34}},
		{0x10203, []byte{0x1, 0x2, 0x3}},
	}

	for _, tt := range tests {
		if enc := int2bytes(tt.Input); bytes.Compare(enc, tt.Expect) != 0 {
			t.Errorf("unexpected base64: expected=%#v but got=%#v", tt.Expect, enc)
		}
	}
}

func TestMakeCert(t *testing.T) {
	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %s", err)
	}
	pub := pri.Public().(*rsa.PublicKey)

	cert, err := makeCert("lauth.example.com", pub, pri)
	if err != nil {
		t.Fatalf("failed to generate certificate: %s", err)
	}

	_, err = x509.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
}
