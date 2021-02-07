package api

import (
	"github.com/macrat/lauth/config"
	"github.com/rs/zerolog/log"
)

func (api LauthAPI) userinfo(subject string, scope *StringSet) (map[string]interface{}, *ErrorMessage) {
	conn, err := api.Connector.Connect()
	if err != nil {
		log.Error().
			Err(err).
			Msg("failed to connecting LDAP server")

		return nil, &ErrorMessage{
			Err:         err,
			Reason:      ServerError,
			Description: "failed to get user info",
		}
	}
	defer conn.Close()

	attrs, err := conn.GetUserAttributes(subject, api.Config.Scopes.AttributesFor(scope.List()))
	if err != nil {
		return nil, &ErrorMessage{
			Err:         err,
			Reason:      InvalidToken,
			Description: "user was not found or disabled",
		}
	}

	maps := api.Config.Scopes.ClaimMapFor(scope.List())
	result := config.MappingClaims(attrs, maps)
	result["sub"] = subject

	return result, nil
}
