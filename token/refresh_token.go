package token

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/macrat/lauth/config"
)

type RefreshTokenClaims struct {
	OIDCClaims

	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

func (claims RefreshTokenClaims) Validate(issuer *config.URL) error {
	if err := claims.OIDCClaims.Validate(issuer, issuer.String()); err != nil {
		return err
	}

	if claims.Type != "REFRESH_TOKEN" {
		return UnexpectedTokenTypeError
	}

	if claims.ClientID == "" {
		return UnexpectedClientIDError
	}

	return nil
}

func (m Manager) CreateRefreshToken(issuer *config.URL, subject, clientID, scope, nonce string, authTime time.Time, expiresIn time.Duration) (string, error) {
	return m.create(RefreshTokenClaims{
		OIDCClaims: OIDCClaims{
			StandardClaims: jwt.StandardClaims{
				Issuer:    issuer.String(),
				Subject:   subject,
				Audience:  issuer.String(),
				ExpiresAt: time.Now().Add(expiresIn).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			Type:     "REFRESH_TOKEN",
			AuthTime: authTime.Unix(),
		},
		ClientID: clientID,
		Scope:    scope,
		Nonce:    nonce,
	})
}

func (m Manager) ParseRefreshToken(token string) (RefreshTokenClaims, error) {
	var claims RefreshTokenClaims
	if _, err := m.parse(token, &claims); err != nil {
		return RefreshTokenClaims{}, err
	}
	return claims, nil
}
