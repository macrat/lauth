package main_test

import (
	"reflect"
	"testing"

	"github.com/macrat/ldapin"
)

func TestScopeConfig(t *testing.T) {
	conf := main.ScopeConfig{
		"profile": {
			{Claim: "name", Attribute: "DisplayName", Type: "string"},
			{Claim: "given_name", Attribute: "GivenName", Type: "string"},
		},
		"email": {
			{Claim: "email", Attribute: "mail", Type: "string"},
		},
	}

	ss := conf.ScopeNames()
	if !reflect.DeepEqual(ss, []string{"profile", "email"}) {
		t.Errorf("ScopeNames returns unexpected value: %#v", ss)
	}

	ss = conf.AllClaims()
	if !reflect.DeepEqual(ss, []string{"name", "given_name", "email"}) {
		t.Errorf("AllClaims returns unexpected value: %#v", ss)
	}

	ss = conf.AttributesFor(main.ParseStringSet("profile"))
	if !reflect.DeepEqual(ss, []string{"DisplayName", "GivenName"}) {
		t.Errorf("AttributesFor returns unexpected value: %#v", ss)
	}

	ss = conf.AttributesFor(main.ParseStringSet("profile email"))
	if !reflect.DeepEqual(ss, []string{"mail", "DisplayName", "GivenName"}) {
		t.Errorf("AttributesFor returns unexpected value: %#v", ss)
	}

	maps := conf.ClaimMapFor(main.ParseStringSet("profile email"))
	if !reflect.DeepEqual(maps, map[string]main.ClaimConfig{
		"DisplayName": {Claim: "name", Attribute: "DisplayName", Type: "string"},
		"GivenName":   {Claim: "given_name", Attribute: "GivenName", Type: "string"},
		"mail":        {Claim: "email", Attribute: "mail", Type: "string"},
	}) {
		t.Errorf("ClaimMapFor returns unexpected value: %#v", maps)
	}
}
