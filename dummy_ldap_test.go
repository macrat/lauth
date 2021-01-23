package main_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/macrat/ldapin"
)

var (
	dummyLDAP = DummyLDAP{
		"macrat": DummyUserInfo{
			Password: "foobar",
			Attributes: map[string][]string{
				"displayName":     {"SHIDA Yuuma"},
				"givenName":       {"yuuma"},
				"sn":              {"shida"},
				"mail":            {"m@crat.jp"},
				"telephoneNumber": {"000-0000-0000"},
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

func (c DummyLDAP) Connect() (main.LDAPSession, error) {
	return c, nil
}

func (c DummyLDAP) Close() error {
	return nil
}

func (c DummyLDAP) LoginTest(username, password string) error {
	if user, ok := c[username]; !ok {
		return main.UserNotFoundError
	} else if user.Password != password {
		return fmt.Errorf("incorrect password")
	}
	return nil
}

func (c DummyLDAP) GetUserAttributes(username string, attributes []string) (map[string][]string, error) {
	user, ok := c[username]
	if !ok {
		return nil, main.UserNotFoundError
	}

	result := make(map[string][]string)
	for _, attr := range attributes {
		if value, ok := user.Attributes[attr]; ok {
			result[attr] = value
		}
	}
	return result, nil
}

func TestDummyLDAP(t *testing.T) {
	if err := dummyLDAP.LoginTest("macrat", "foobar"); err != nil {
		t.Errorf("expected success to login but failed: %s", err)
	}
	if err := dummyLDAP.LoginTest("macrat", "hello"); err == nil {
		t.Errorf("expected fail to login but succeed")
	}

	if attrs, err := dummyLDAP.GetUserAttributes("macrat", []string{"displayName", "noSuchAttr"}); err != nil {
		t.Errorf("failed to get attributes: %s", err)
	} else if !reflect.DeepEqual(attrs, map[string][]string{"displayName": {"SHIDA Yuuma"}}) {
		t.Errorf("unexpected attributes: %s", attrs)
	}

	if _, err := dummyLDAP.GetUserAttributes("noone", []string{"displayName", "noSuchAttr"}); err == nil {
		t.Errorf("expected fail to get attributes but succeed")
	} else if err != main.UserNotFoundError {
		t.Errorf("unexpected error: %s", err)
	}
}
