package token

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/macrat/ldapin/config"
)

type IDTokenClaims struct {
	OIDCClaims

	Nonce string `json:"nonce,omitempty"`
}

func (claims IDTokenClaims) Validate(issuer *config.URL, audience string) error {
	if err := claims.OIDCClaims.Validate(issuer, audience); err != nil {
		return err
	}

	if claims.Type != "ID_TOKEN" {
		return UnexpectedTokenTypeError
	}

	return nil
}

func (m Manager) CreateIDToken(issuer *config.URL, subject, audience, nonce string, authTime time.Time, expiresIn time.Duration) (string, error) {
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

func (m Manager) ParseIDToken(token string) (IDTokenClaims, error) {
	var claims IDTokenClaims
	if _, err := m.parse(token, &claims); err != nil {
		return IDTokenClaims{}, err
	}
	return claims, nil
}
