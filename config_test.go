package main_test

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

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

func TestConfig_Override(t *testing.T) {
	conf := &main.LdapinConfig{}

	if !reflect.DeepEqual(conf, &main.LdapinConfig{}) {
		t.Errorf("expected empty but got %#v", conf)
	}

	conf.Override(&main.LdapinConfig{
		TTL: main.TTLConfig{
			Code: main.Duration(42 * time.Minute),
		},
	})
	if !reflect.DeepEqual(conf, &main.LdapinConfig{TTL: main.TTLConfig{Code: main.Duration(42 * time.Minute)}}) {
		t.Errorf("expected set code ttl but got %#v", conf)
	}

	conf.Override(main.DefaultConfig)
	if !reflect.DeepEqual(conf, main.DefaultConfig) {
		t.Errorf("expected equals default config but got %#v", conf)
	}
}

func TestLoadConfig(t *testing.T) {
	raw := strings.NewReader(`
issuer: http://example.com:1234
listen: ":4200"

ttl:
  code: 5m
  token: 42d
`)
	conf, err := main.LoadConfig(raw)
	if err != nil {
		t.Fatalf("failed to load config: %s", err)
	}

	if conf.Issuer.String() != "http://example.com:1234" {
		t.Errorf("unexpected issuer: %s", conf.Issuer)
	}

	if conf.Listen.String() != ":4200" {
		t.Errorf("unexpected listen address: %s", conf.Listen)
	}

	if time.Duration(conf.TTL.Code) != 5*time.Minute {
		t.Errorf("unexpected code TTL: %d", conf.TTL.Code)
	}

	if time.Duration(conf.TTL.Token) != 42*24*time.Hour {
		t.Errorf("unexpected token TTL: %d", conf.TTL.Token)
	}
}

func TestConfigExampleLoadable(t *testing.T) {
	f, err := os.Open("./config.example.yml")
	if err != nil {
		t.Fatalf("failed to open example config: %s", err)
	}

	_, err = main.LoadConfig(f)
	if err != nil {
		t.Errorf("failed to load example config: %s", err)
	}
}
