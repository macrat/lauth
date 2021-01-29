package token

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/macrat/ldapin/config"
)

type CodeClaims struct {
	OIDCClaims

	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Nonce       string `json:"nonce,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

func (claims CodeClaims) Validate(issuer *config.URL) error {
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

func (m Manager) CreateCode(issuer *config.URL, subject, clientID, redirectURI, scope, nonce string, authTime time.Time, expiresIn time.Duration) (string, error) {
	plain, err := m.create(CodeClaims{
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
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		Nonce:       nonce,
	})
	if err != nil {
		return "", err
	}

	return m.encryptToken(plain)
}

func (m Manager) ParseCode(token string) (CodeClaims, error) {
	dec, err := m.decryptToken(token)
	if err != nil {
		return CodeClaims{}, err
	}

	var claims CodeClaims
	if _, err := m.parse(dec, &claims); err != nil {
		return CodeClaims{}, err
	}
	return claims, nil
}
