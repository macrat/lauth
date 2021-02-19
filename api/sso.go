package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/token"
)

const (
	SSO_TOKEN_COOKIE = "lauth_token"
)

func (api *LauthAPI) SetSSOToken(c *gin.Context, subject, client string, authenticated bool) error {
	authTime := time.Now()
	expiresAt := time.Now().Add(api.Config.Expire.SSO.Duration())
	azp := token.AuthorizedParties{client}

	if current, err := api.GetSSOToken(c); err == nil {
		if !authenticated {
			authTime = time.Unix(current.AuthTime, 0)
			expiresAt = time.Unix(current.ExpiresAt, 0)
		}
		azp = current.Authorized.Append(client)
	}

	token, err := api.TokenManager.CreateSSOToken(
		api.Config.Issuer,
		subject,
		azp,
		authTime,
		expiresAt,
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
		api.Config.Issuer.Hostname(),
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
	c.SetCookie(SSO_TOKEN_COOKIE, "", 0, "/", api.Config.Issuer.Hostname(), secure, true)
}
