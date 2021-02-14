package token

import (
	"time"

	"github.com/macrat/lauth/config"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

type SSOTokenClaims struct {
	OIDCClaims

	//Authorized []string `json:"azp,omitempty"` // TODO: use this
}

func (claims SSOTokenClaims) Validate(issuer *config.URL) error {
	if err := claims.OIDCClaims.Validate(issuer, issuer.String()); err != nil {
		return err
	}

	if claims.Type != "SSO_TOKEN" {
		return UnexpectedTokenTypeError
	}

	return nil
}

func (m Manager) CreateSSOToken(issuer *config.URL, subject string, authTime time.Time, expiresIn time.Duration) (string, error) {
	return m.create(SSOTokenClaims{
		OIDCClaims: OIDCClaims{
			StandardClaims: jwt.StandardClaims{
				Issuer:    issuer.String(),
				Subject:   subject,
				Audience:  issuer.String(),
				ExpiresAt: time.Now().Add(expiresIn).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			Type:     "SSO_TOKEN",
			AuthTime: authTime.Unix(),
		},
	})
}

func (m Manager) ParseSSOToken(token string) (SSOTokenClaims, error) {
	var claims SSOTokenClaims
	if _, err := m.parse(token, &claims); err != nil {
		return SSOTokenClaims{}, err
	}
	return claims, nil
}
