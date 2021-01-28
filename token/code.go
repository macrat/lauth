package token

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/macrat/ldapin/config"
)

type CodeClaims struct {
	OIDCClaims

	ClientID string `json:"client_id"`
	Nonce    string `json:"nonce"`
	Scope    string `json:"scope,omitempty"`
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

func (m Manager) CreateCode(issuer *config.URL, subject, clientID, scope, nonce string, authTime time.Time, expiresIn time.Duration) (string, error) {
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

func (m Manager) ParseCode(token string) (CodeClaims, error) {
	var claims CodeClaims
	if _, err := m.parse(token, &claims); err != nil {
		return CodeClaims{}, err
	}
	return claims, nil
}
