package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

var (
	InvalidTokenError        = fmt.Errorf("invalid token")
	UnexpectedIssuerError    = fmt.Errorf("unexpected issuer")
	UnexpectedAudienceError  = fmt.Errorf("unexpected audience")
	UnexpectedTokenTypeError = fmt.Errorf("unexpected token type")
	UnexpectedClientIDError  = fmt.Errorf("unexpected client_id")
)

type OIDCClaims struct {
	jwt.StandardClaims

	Type     string `json:"typ"`
	AuthTime int64  `json:"auth_time"`
}

func (claims OIDCClaims) Validate(issuer *URL, audience string) error {
	if err := claims.StandardClaims.Valid(); err != nil {
		return err
	}

	if claims.Issuer != issuer.String() {
		return UnexpectedIssuerError
	}

	if claims.Audience != audience {
		return UnexpectedAudienceError
	}

	return nil
}

type CodeClaims struct {
	OIDCClaims

	ClientID string `json:"client_id"`
	Nonce    string `json:"nonce"`
	Scope    string `json:"scope,omitempty"`
}

func (claims CodeClaims) Validate(issuer *URL) error {
	if err := claims.OIDCClaims.Validate(issuer, issuer.String()); err != nil {
		return err
	}

	if claims.Type != "CODE" {
		return UnexpectedTokenTypeError
	}

	if claims.ClientID == "" {
		return UnexpectedClientIDError
	}

	return nil
}

type AccessTokenClaims struct {
	OIDCClaims

	Scope string `json:"scope,omitempty"`
}

func (claims AccessTokenClaims) Validate(issuer *URL) error {
	if err := claims.OIDCClaims.Validate(issuer, issuer.String()); err != nil {
		return err
	}

	if claims.Type != "ACCESS_TOKEN" {
		return UnexpectedTokenTypeError
	}

	return nil
}

type IDTokenClaims struct {
	OIDCClaims

	Nonce string `json:"nonce,omitempty"`
}

func (claims IDTokenClaims) Validate(issuer *URL, audience string) error {
	if err := claims.OIDCClaims.Validate(issuer, audience); err != nil {
		return err
	}

	if claims.Type != "ID_TOKEN" {
		return UnexpectedTokenTypeError
	}

	return nil
}

type JWTManager struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

func NewJWTManager(private *rsa.PrivateKey) (JWTManager, error) {
	return JWTManager{
		private: private,
		public:  private.Public().(*rsa.PublicKey),
	}, nil
}

func GenerateJWTManager() (JWTManager, error) {
	pri, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return JWTManager{}, err
	}
	return NewJWTManager(pri)
}

func NewJWTManagerFromFile(file io.Reader) (JWTManager, error) {
	raw, err := ioutil.ReadAll(file)
	if err != nil {
		return JWTManager{}, err
	}

	pri, err := jwt.ParseRSAPrivateKeyFromPEM(raw)
	if err != nil {
		return JWTManager{}, err
	}

	return NewJWTManager(pri)
}

func (m JWTManager) PublicKey() *rsa.PublicKey {
	return m.public
}

func (m JWTManager) KeyID() uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceX500, x509.MarshalPKCS1PublicKey(m.public))
}

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
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, uint64(i))
	skip := 0
	for skip < 8 && bytes[skip] == 0x00 {
		skip++
	}
	return bytes2base64(bytes[skip:])
}

func (m JWTManager) JWKs() ([]JWK, error) {
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

func (m JWTManager) create(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.KeyID().String()
	return token.SignedString(m.private)
}

func (m JWTManager) CreateCode(issuer *URL, subject, clientID, scope, nonce string, authTime time.Time, expiresIn time.Duration) (string, error) {
	return m.create(CodeClaims{
		OIDCClaims: OIDCClaims{
			StandardClaims: jwt.StandardClaims{
				Issuer:    issuer.String(),
				Subject:   subject,
				Audience:  issuer.String(),
				ExpiresAt: time.Now().Add(expiresIn).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			Type:     "CODE",
			AuthTime: authTime.Unix(),
		},
		ClientID: clientID,
		Scope:    scope,
		Nonce:    nonce,
	})
}

func (m JWTManager) CreateAccessToken(issuer *URL, subject, scope string, authTime time.Time, expiresIn time.Duration) (string, error) {
	return m.create(AccessTokenClaims{
		OIDCClaims: OIDCClaims{
			StandardClaims: jwt.StandardClaims{
				Issuer:    issuer.String(),
				Subject:   subject,
				Audience:  issuer.String(),
				ExpiresAt: time.Now().Add(expiresIn).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			Type:     "ACCESS_TOKEN",
			AuthTime: authTime.Unix(),
		},
		Scope: scope,
	})
}

func (m JWTManager) CreateIDToken(issuer *URL, subject, audience, nonce string, authTime time.Time, expiresIn time.Duration) (string, error) {
	return m.create(IDTokenClaims{
		OIDCClaims: OIDCClaims{
			StandardClaims: jwt.StandardClaims{
				Issuer:    issuer.String(),
				Subject:   subject,
				Audience:  audience,
				ExpiresAt: time.Now().Add(expiresIn).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			Type:     "ID_TOKEN",
			AuthTime: authTime.Unix(),
		},
		Nonce: nonce,
	})
}

func (m JWTManager) parse(token string, claims jwt.Claims) (*jwt.Token, error) {
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return m.public, nil
	})

	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, InvalidTokenError
	}
	return parsed, nil
}

func (m JWTManager) ParseCode(token string) (CodeClaims, error) {
	var claims CodeClaims
	if _, err := m.parse(token, &claims); err != nil {
		return CodeClaims{}, err
	}
	return claims, nil
}

func (m JWTManager) ParseAccessToken(token string) (AccessTokenClaims, error) {
	var claims AccessTokenClaims
	if _, err := m.parse(token, &claims); err != nil {
		return AccessTokenClaims{}, err
	}
	return claims, nil
}

func (m JWTManager) ParseIDToken(token string) (IDTokenClaims, error) {
	var claims IDTokenClaims
	if _, err := m.parse(token, &claims); err != nil {
		return IDTokenClaims{}, err
	}
	return claims, nil
}
