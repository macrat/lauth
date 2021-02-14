package api

import (
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/token"
)

const (
	SSO_TOKEN_COOKIE = "lauth_token"
)

func (api *LauthAPI) SetSSOToken(c *gin.Context, subject string) error {
	token, err := api.TokenManager.CreateSSOToken(
		api.Config.Issuer,
		subject,
		time.Now(),
		time.Duration(api.Config.Expire.SSO),
	)
	if err != nil {
		return err
	}

	secure := api.Config.Issuer.Scheme == "https"
	c.SetCookie(
		SSO_TOKEN_COOKIE,
		token,
		int(api.Config.Expire.SSO.IntSeconds()),
		"/",
		(*url.URL)(api.Config.Issuer).Hostname(),
		secure,
		true,
	)

	return nil
}

func (api *LauthAPI) GetSSOToken(c *gin.Context) (token.SSOTokenClaims, error) {
	rawToken, err := c.Cookie(SSO_TOKEN_COOKIE)
	if err != nil {
		return token.SSOTokenClaims{}, err
	}

	ssoToken, err := api.TokenManager.ParseSSOToken(rawToken)
	if err != nil {
		return token.SSOTokenClaims{}, err
	}

	err = ssoToken.Validate(api.Config.Issuer)
	if err != nil {
		return token.SSOTokenClaims{}, err
	}

	return ssoToken, nil
}

func (api *LauthAPI) DeleteSSOToken(c *gin.Context) {
	secure := api.Config.Issuer.Scheme == "https"
	c.SetCookie(SSO_TOKEN_COOKIE, "", 0, "/", (*url.URL)(api.Config.Issuer).Hostname(), secure, true)
}
