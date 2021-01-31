package config

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func GetDCByDN(dn string) (string, error) {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return "", err
	}

	var result []string

	for _, rdn := range parsed.RDNs {
		for _, attr := range rdn.Attributes {
			if attr.Type == "DC" {
				result = append(result, fmt.Sprintf("%s=%s", attr.Type, attr.Value))
			}
		}
	}

	return strings.Join(result, ","), nil
}
