package api

import (
	"errors"
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

func (api *LauthAPI) ValidateLoginSession(token, userIP, clientID string) error {
	if token == "" {
		return errors.New("session token is empty")
	}

	parsed, err := api.TokenManager.ParseLoginToken(token)
	if err != nil {
		return err
	}
	if err = parsed.Validate(api.Config.Issuer); err != nil {
		return err
	}

	if parsed.Subject != userIP {
		return errors.New("mismatch User IP")
	}
	if parsed.ClientID != clientID {
		return errors.New("mismatch Client ID")
	}

	return nil
}
