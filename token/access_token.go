package token

import (
	"time"

	"github.com/macrat/lauth/config"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

type AccessTokenClaims struct {
	OIDCClaims

	AuthorizedParties []string `json:"azp,omitempty"`
	Scope             string   `json:"scope,omitempty"`
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

func (m Manager) CreateAccessToken(issuer *config.URL, subject, clientID, scope string, authTime time.Time, expiresIn time.Duration) (string, error) {
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
		AuthorizedParties: []string{clientID},
		Scope:             scope,
	})
}

func (m Manager) ParseAccessToken(token string) (AccessTokenClaims, error) {
	var claims AccessTokenClaims
	if _, err := m.parse(token, &claims); err != nil {
		return AccessTokenClaims{}, err
	}
	return claims, nil
}
