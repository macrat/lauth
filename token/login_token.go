package token

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/macrat/ldapin/config"
)

type LoginTokenClaims struct {
	OIDCClaims

	ClientID string `json:"client_id"`
}

func (claims LoginTokenClaims) Validate(issuer *config.URL) error {
	if err := claims.OIDCClaims.Validate(issuer, issuer.String()); err != nil {
		return err
	}

	if claims.Type != "LOGIN_TOKEN" {
		return UnexpectedTokenTypeError
	}

	return nil
}

func (m Manager) CreateLoginToken(issuer *config.URL, subject, clientID string, expiresIn time.Duration) (string, error) {
	return m.create(LoginTokenClaims{
		OIDCClaims: OIDCClaims{
			StandardClaims: jwt.StandardClaims{
				Issuer:    issuer.String(),
				Subject:   subject,
				Audience:  issuer.String(),
				ExpiresAt: time.Now().Add(expiresIn).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			Type: "LOGIN_TOKEN",
		},
		ClientID: clientID,
	})
}

func (m Manager) ParseLoginToken(token string) (LoginTokenClaims, error) {
	var claims LoginTokenClaims
	if _, err := m.parse(token, &claims); err != nil {
		return LoginTokenClaims{}, err
	}
	return claims, nil
}
