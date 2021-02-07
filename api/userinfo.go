package api

import (
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/metrics"
	"github.com/rs/zerolog/log"
)

func (api *LauthAPI) userinfo(subject string, scope *StringSet) (map[string]interface{}, *ErrorMessage) {
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

func (api *LauthAPI) userinfoByToken(rawToken string, report *metrics.Context) (map[string]interface{}, *ErrorMessage) {
	token, err := api.TokenManager.ParseAccessToken(rawToken)
	if err == nil {
		report.Set("client_id", token.Audience)
		report.Set("username", token.Subject)
		err = token.Validate(api.Config.Issuer)
	}

	if err != nil {
		return nil, &ErrorMessage{
			Err:         err,
			Reason:      InvalidToken,
			Description: "token is invalid",
		}
	}

	scope := ParseStringSet(token.Scope)
	return api.userinfo(token.Subject, scope)
}
