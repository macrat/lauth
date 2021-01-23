package main_test

import (
	"reflect"
	"testing"
	"sort"

	"github.com/macrat/ldapin"
)

func SameStringSet(xs []string, ys []string) bool {
	sort.Strings(xs)
	sort.Strings(ys)
	return reflect.DeepEqual(xs, ys)
}

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
	if !SameStringSet(ss, []string{"profile", "email"}) {
		t.Errorf("ScopeNames returns unexpected value: %#v", ss)
	}

	ss = conf.AllClaims()
	if !SameStringSet(ss, []string{"name", "given_name", "email"}) {
		t.Errorf("AllClaims returns unexpected value: %#v", ss)
	}

	ss = conf.AttributesFor(main.ParseStringSet("profile"))
	if !SameStringSet(ss, []string{"DisplayName", "GivenName"}) {
		t.Errorf("AttributesFor returns unexpected value: %#v", ss)
	}

	ss = conf.AttributesFor(main.ParseStringSet("profile email"))
	if !SameStringSet(ss, []string{"mail", "DisplayName", "GivenName"}) {
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
