package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestBytes2base64(t *testing.T) {
	if enc := bytes2base64([]byte("hello world")); enc != "aGVsbG8gd29ybGQ" {
		t.Errorf("unexpected base64: %s", enc)
	}
}

func TestInt2base64(t *testing.T) {
	tests := []struct {
		Input  int
		Expect string
	}{
		{0, ""},
		{1234, "BNI"},
		{65537, "AQAB"},
	}

	for _, tt := range tests {
		if enc := int2base64(tt.Input); enc != tt.Expect {
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

	certStr, err := makeCert("lauth.example.com", pub, pri)
	if err != nil {
		t.Fatalf("failed to generate certificate: %s", err)
	}

	b, err := base64.StdEncoding.Strict().DecodeString(certStr)
	if err != nil {
		t.Fatalf("failed to decode certificate as base64: %s", err)
	}

	_, err = x509.ParseCertificate(b)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
}
