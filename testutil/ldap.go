package testutil

import (
	"fmt"

	"github.com/macrat/ldapin/ldap"
)

var (
	LDAP = DummyLDAP{
		"macrat": DummyUserInfo{
			Password: "foobar",
			Attributes: map[string][]string{
				"displayName":     {"SHIDA Yuuma"},
				"givenName":       {"yuuma"},
				"sn":              {"shida"},
				"mail":            {"m@crat.jp"},
				"telephoneNumber": {"000-1234-5678"},
			},
		},
		"j.smith": DummyUserInfo{
			Password: "hello",
			Attributes: map[string][]string{
				"displayName": {"Jhon smith"},
				"givenName":   {"jhon"},
				"sn":          {"smith"},
				"mail":        {"jhon@example.com"},
			},
		},
	}
)

type DummyUserInfo struct {
	Password   string
	Attributes map[string][]string
}

type DummyLDAP map[string]DummyUserInfo

func (c DummyLDAP) Connect() (ldap.LDAPSession, error) {
	return c, nil
}

func (c DummyLDAP) Close() error {
	return nil
}

func (c DummyLDAP) LoginTest(username, password string) error {
	if user, ok := c[username]; !ok {
		return ldap.UserNotFoundError
	} else if user.Password != password {
		return fmt.Errorf("incorrect password")
	}
	return nil
}

func (c DummyLDAP) GetUserAttributes(username string, attributes []string) (map[string][]string, error) {
	user, ok := c[username]
	if !ok {
		return nil, ldap.UserNotFoundError
	}

	result := make(map[string][]string)
	for _, attr := range attributes {
		if value, ok := user.Attributes[attr]; ok {
			result[attr] = value
		}
	}
	return result, nil
}
