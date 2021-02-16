package token

import (
	"github.com/macrat/lauth/config"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

type RequestObjectClaims struct {
	jwt.StandardClaims

	ResponseType string `json:"response_type,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	Scope        string `json:"scope,omitempty"`
	State        string `json:"state,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	MaxAge       int64  `json:"max_age,omitempty"`
	Prompt       string `json:"prompt,omitempty"`
	LoginHint    string `json:"login_hint,omitempty"`
}

func (claims RequestObjectClaims) Validate(issuer *config.URL, clientID string) error {
	if err := claims.StandardClaims.Valid(); err != nil {
		return err
	}

	if claims.Audience != issuer.String() {
		return UnexpectedAudienceError
	}

	if claims.Issuer != clientID {
		return UnexpectedIssuerError
	}

	return nil
}

func (m Manager) ParseRequestObject(token string, signKey string) (RequestObjectClaims, error) {
	var claims RequestObjectClaims

	parsed, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		if kid, ok := t.Header["kid"].(string); ok && kid == m.KeyID().String() {
			return m.public, nil
		}
		return jwt.ParseRSAPublicKeyFromPEM([]byte(signKey))
	})
	if err != nil {
		return RequestObjectClaims{}, err
	}

	if !parsed.Valid {
		return RequestObjectClaims{}, InvalidTokenError
	}

	return claims, nil
}
