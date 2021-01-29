package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
)

func TokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))

	buf := bytes.NewBuffer([]byte{})
	enc := base64.NewEncoder(base64.RawURLEncoding, buf)
	enc.Write(hash[:128/8])
	enc.Close()

	return string(buf.Bytes())
}
