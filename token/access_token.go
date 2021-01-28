package token

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/macrat/ldapin/config"
)

type AccessTokenClaims struct {
	OIDCClaims

	Scope string `json:"scope,omitempty"`
}

func (claims AccessTokenClaims) Validate(issuer *config.URL) error {
	if err := claims.OIDCClaims.Validate(issuer, issuer.String()); err != nil {
		return err
	}

	if claims.Type != "ACCESS_TOKEN" {
		return UnexpectedTokenTypeError
	}

	return nil
}

func (m Manager) CreateAccessToken(issuer *config.URL, subject, scope string, authTime time.Time, expiresIn time.Duration) (string, error) {
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

func (m Manager) ParseAccessToken(token string) (AccessTokenClaims, error) {
	var claims AccessTokenClaims
	if _, err := m.parse(token, &claims); err != nil {
		return AccessTokenClaims{}, err
	}
	return claims, nil
}
