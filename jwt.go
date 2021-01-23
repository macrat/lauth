package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
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

func (claims OIDCClaims) Validate(issuer, audience string) error {
	if err := claims.StandardClaims.Valid(); err != nil {
		return err
	}

	if claims.Issuer != issuer {
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
	Scope    string `json:"scope,omitempty"`
}

func (claims CodeClaims) Validate(issuer string) error {
	if err := claims.OIDCClaims.Validate(issuer, issuer); err != nil {
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

func (claims AccessTokenClaims) Validate(issuer string) error {
	if err := claims.OIDCClaims.Validate(issuer, issuer); err != nil {
		return err
	}

	if claims.Type != "ACCESS_TOKEN" {
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

func (m JWTManager) JWKs() (interface{}, error) {
	k := jwk.NewRSAPublicKey()
	if err := k.FromRaw(m.public); err != nil {
		return nil, err
	}
	return []jwk.Key{k}, nil
}

func (m JWTManager) create(claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(m.private)
}

func (m JWTManager) CreateCode(issuer, subject, clientID, scope string, authTime time.Time, expiresIn time.Duration) (string, error) {
	return m.create(CodeClaims{
		OIDCClaims: OIDCClaims{
			StandardClaims: jwt.StandardClaims{
				Issuer:    issuer,
				Subject:   subject,
				Audience:  issuer,
				ExpiresAt: time.Now().Add(expiresIn).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			Type:     "CODE",
			AuthTime: authTime.Unix(),
		},
		ClientID: clientID,
		Scope:    scope,
	})
}

func (m JWTManager) CreateAccessToken(issuer, subject, scope string, authTime time.Time, expiresIn time.Duration) (string, error) {
	return m.create(AccessTokenClaims{
		OIDCClaims: OIDCClaims{
			StandardClaims: jwt.StandardClaims{
				Issuer:    issuer,
				Subject:   subject,
				Audience:  issuer,
				ExpiresAt: time.Now().Add(expiresIn).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			Type:     "ACCESS_TOKEN",
			AuthTime: authTime.Unix(),
		},
		Scope: scope,
	})
}

func (m JWTManager) CreateIDToken(issuer, subject, audience string, authTime time.Time, expiresIn time.Duration) (string, error) {
	return m.create(OIDCClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  audience,
			ExpiresAt: time.Now().Add(expiresIn).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		Type:     "ID_TOKEN",
		AuthTime: authTime.Unix(),
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
