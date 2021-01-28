package token

import (
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
