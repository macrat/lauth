package api

import (
	"time"
)

func (api *LauthAPI) MakeLoginSession(userIP, clientID string) (string, error) {
	return api.TokenManager.CreateLoginToken(
		api.Config.Issuer,
		userIP,
		clientID,
		time.Duration(api.Config.Expire.Login),
	)
}

func (api *LauthAPI) IsValidLoginSession(token, userIP, clientID string) bool {
	if token == "" {
		return false
	}

	parsed, err := api.TokenManager.ParseLoginToken(token)
	if err != nil || parsed.Validate(api.Config.Issuer) != nil {
		return false
	}

	if parsed.Subject != userIP || parsed.ClientID != clientID {
		return false
	}

	return true
}
