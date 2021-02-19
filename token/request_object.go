package token

import (
	"time"

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

func (claims RequestObjectClaims) Validate(issuer string, audience *config.URL) error {
	if err := claims.StandardClaims.Valid(); err != nil {
		return err
	}

	if claims.Issuer != issuer {
		return UnexpectedIssuerError
	}

	if claims.Audience != audience.String() {
		return UnexpectedAudienceError
	}

	return nil
}

func (m Manager) CreateRequestObject(issuer *config.URL, subject string, request RequestObjectClaims, expiresAt time.Time) (string, error) {
	request.Issuer = issuer.String()
	request.Subject = subject
	request.Audience = issuer.String()
	request.ExpiresAt = expiresAt.Unix()
	request.IssuedAt = time.Now().Unix()

	return m.create(request)
}

func (m Manager) ParseRequestObject(token string, signKey string) (RequestObjectClaims, error) {
	var claims RequestObjectClaims
	if _, err := m.parse(token, signKey, &claims); err != nil {
		return RequestObjectClaims{}, err
	}
	return claims, nil
}
