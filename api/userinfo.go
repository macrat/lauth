package api

import (
	"log"

	"github.com/macrat/ldapin/config"
)

func (api LdapinAPI) userinfo(subject string, scope *StringSet) (map[string]interface{}, error) {
	conn, err := api.Connector.Connect()
	if err != nil {
		log.Printf("failed to connect LDAP server: %s", err)
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
