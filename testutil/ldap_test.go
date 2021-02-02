package testutil_test

import (
	"reflect"
	"testing"

	"github.com/macrat/lauth/ldap"
	"github.com/macrat/lauth/testutil"
)

func TestDummyLDAP(t *testing.T) {
	if err := testutil.LDAP.LoginTest("macrat", "foobar"); err != nil {
		t.Errorf("expected success to login but failed: %s", err)
	}
	if err := testutil.LDAP.LoginTest("macrat", "hello"); err == nil {
		t.Errorf("expected fail to login but succeed")
	}

	if attrs, err := testutil.LDAP.GetUserAttributes("macrat", []string{"displayName", "noSuchAttr"}); err != nil {
		t.Errorf("failed to get attributes: %s", err)
	} else if !reflect.DeepEqual(attrs, map[string][]string{"displayName": {"SHIDA Yuuma"}}) {
		t.Errorf("unexpected attributes: %s", attrs)
	}

	if _, err := testutil.LDAP.GetUserAttributes("noone", []string{"displayName", "noSuchAttr"}); err == nil {
		t.Errorf("expected fail to get attributes but succeed")
	} else if err != ldap.UserNotFoundError {
		t.Errorf("unexpected error: %s", err)
	}
}
