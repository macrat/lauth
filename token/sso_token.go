package token

import (
	"time"

	"github.com/macrat/lauth/config"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

type AuthorizedParties []string

func (azp AuthorizedParties) Includes(rp string) bool {
	for _, p := range azp {
		if p == rp {
			return true
		}
	}
	return false
}

func (azp AuthorizedParties) Append(rp string) AuthorizedParties {
	if azp.Includes(rp) {
		return azp
	}
	return append(azp, rp)
}

type SSOTokenClaims struct {
	OIDCClaims

	Authorized AuthorizedParties `json:"azp,omitempty"`
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

func (m Manager) CreateSSOToken(issuer *config.URL, subject string, authorized AuthorizedParties, authTime time.Time, expiresAt time.Time) (string, error) {
	return m.create(SSOTokenClaims{
		OIDCClaims: OIDCClaims{
			StandardClaims: jwt.StandardClaims{
				Issuer:    issuer.String(),
				Subject:   subject,
				Audience:  issuer.String(),
				ExpiresAt: expiresAt.Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			Type:     "SSO_TOKEN",
			AuthTime: authTime.Unix(),
		},
		Authorized: authorized,
	})
}

func (m Manager) ParseSSOToken(token string) (SSOTokenClaims, error) {
	var claims SSOTokenClaims
	if _, err := m.parse(token, "", &claims); err != nil {
		return SSOTokenClaims{}, err
	}
	return claims, nil
}
