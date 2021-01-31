package api

import (
	"github.com/macrat/ldapin/config"
	"github.com/rs/zerolog/log"
)

func (api LdapinAPI) userinfo(subject string, scope *StringSet) (map[string]interface{}, error) {
	conn, err := api.Connector.Connect()
	if err != nil {
		log.Error().
			Err(err).
			Msg("failed to connecting LDAP server")

		return nil, err
	}
	defer conn.Close()

	attrs, err := conn.GetUserAttributes(subject, api.Config.Scopes.AttributesFor(scope.List()))
	if err != nil {
		return nil, err
	}

	maps := api.Config.Scopes.ClaimMapFor(scope.List())
	result := config.MappingClaims(attrs, maps)
	result["sub"] = subject

	return result, nil
}
