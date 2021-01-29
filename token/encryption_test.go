package token

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestTokenEncryption(t *testing.T) {
	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to make secret key: %s", err)
	}
	manager, err := NewManager(pri)
	if err != nil {
		t.Fatalf("failed to make token manager: %s", err)
	}

	message := "hello world"

	enc, err := manager.encryptToken(message)
	if err != nil {
		t.Fatalf("failed to encryption message: %s", err)
	}

	dec, err := manager.decryptToken(enc)
	if err != nil {
		t.Fatalf("failed to decryption message: %s", err)
	}

	if dec != message {
		t.Errorf("decrypted text was not match\n input: %#v\noutput: %#v", message, dec)
	}
}
