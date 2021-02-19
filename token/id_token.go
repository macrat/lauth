package token

import (
	"encoding/json"
	"time"

	"github.com/macrat/lauth/config"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

type ExtraClaims map[string]interface{}

type IDTokenClaims struct {
	OIDCClaims

	Nonce           string      `json:"nonce,omitempty"`
	CodeHash        string      `json:"c_hash,omitempty"`
	AccessTokenHash string      `json:"at_hash,omitempty"`
	ExtraClaims     ExtraClaims `json:"-"`
}

func (claims IDTokenClaims) MarshalJSON() ([]byte, error) {
	c := make(jwt.MapClaims)

	for k, v := range claims.ExtraClaims {
		c[k] = v
	}

	c["exp"] = claims.ExpiresAt
	c["iat"] = claims.IssuedAt

	c["iss"] = claims.Issuer
	c["sub"] = claims.Subject
	c["aud"] = claims.Audience

	c["typ"] = claims.Type
	c["auth_time"] = claims.AuthTime

	if claims.Nonce != "" {
		c["nonce"] = claims.Nonce
	}

	if claims.CodeHash != "" {
		c["c_hash"] = claims.CodeHash
	}

	if claims.AccessTokenHash != "" {
		c["at_hash"] = claims.AccessTokenHash
	}

	return json.Marshal(c)
}

func (claims *IDTokenClaims) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &claims.OIDCClaims); err != nil {
		return err
	}

	c := make(ExtraClaims)
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}

	claims.Nonce, _ = c["nonce"].(string)
	claims.CodeHash, _ = c["c_hash"].(string)
	claims.AccessTokenHash, _ = c["at_hash"].(string)

	for k := range c {
		switch k {
		case "exp", "iat", "iss", "sub", "aud", "typ", "auth_time", "nbt", "jti", "nonce", "c_hash", "at_hash":
			delete(c, k)
		}
	}
	claims.ExtraClaims = c

	return nil
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

func (m Manager) CreateIDToken(issuer *config.URL, subject, audience, nonce, code, accessToken string, extraClaims ExtraClaims, authTime time.Time, expiresIn time.Duration) (string, error) {
	codeHash := ""
	if code != "" {
		codeHash = TokenHash(code)
	}

	accessTokenHash := ""
	if accessToken != "" {
		accessTokenHash = TokenHash(accessToken)
	}

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
		Nonce:           nonce,
		CodeHash:        codeHash,
		AccessTokenHash: accessTokenHash,
		ExtraClaims:     extraClaims,
	})
}

func (m Manager) ParseIDToken(token string) (IDTokenClaims, error) {
	var claims IDTokenClaims
	if _, err := m.parse(token, "", &claims); err != nil {
		return IDTokenClaims{}, err
	}
	return claims, nil
}
