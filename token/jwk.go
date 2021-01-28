package token

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
)

type JWK struct {
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyType   string `json:"kty"`
	E         string `json:"e"`
	N         string `json:"n"`
}

func bytes2base64(b []byte) string {
	buf := bytes.NewBuffer([]byte{})
	enc := base64.NewEncoder(base64.RawURLEncoding, buf)
	enc.Write(b)
	enc.Close()
	return string(buf.Bytes())
}

func int2base64(i int) string {
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(i))
	skip := 0
	for skip < 8 && bs[skip] == 0x00 {
		skip++
	}
	return bytes2base64(bs[skip:])
}

func (m Manager) JWKs() ([]JWK, error) {
	return []JWK{
		{
			KeyID:     m.KeyID().String(),
			Use:       "sig",
			Algorithm: "RS256",
			KeyType:   "RSA",
			E:         int2base64(m.public.E),
			N:         bytes2base64(m.public.N.Bytes()),
		},
	}, nil
}
