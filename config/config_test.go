package config_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/macrat/lauth/config"
)

func TestTakeOptions(t *testing.T) {
	type Child struct {
		Hello string `toml:"hello"                flag:"child-hello"`
		World int    `toml:"world_conf,omitempty" flag:"child-world"`
	}
	type Config struct {
		Child     Child  `toml:"child"`
		Parent    string `toml:"parent"     flag:"parent-flag"`
		NoInclude string `toml:"no_include"`
	}

	result := map[string]string{}
	config.TakeOptions("", reflect.TypeOf(Config{}), result)

	expect := map[string]string{
		"child.hello":      "child-hello",
		"child.world_conf": "child-world",
		"parent":           "parent-flag",
	}

	if !reflect.DeepEqual(result, expect) {
		t.Errorf("unexpected options:\nexpected: %#v\n but got: %#v", expect, result)
	}
}

func TestLoadConfig(t *testing.T) {
	raw := strings.NewReader(`
issuer = "http://example.com:1234"
listen = ":4200"

[expire]
code = "5m"
token = "42d"

[ldap]
server = "ldap://someone:secure@ldap.example.com"

[client.test]
secret = "$2a$10$fU1PBoQ6V4a3Mbg4BI5yJemdSU4bE5LogDMFG55n5C761X0/tzAkW"
`)
	conf := &config.Config{}

	if err := conf.ReadReader(raw); err != nil {
		t.Fatalf("failed to load config: %s", err)
	}

	if conf.Issuer.String() != "http://example.com:1234" {
		t.Errorf("unexpected issuer: %s", conf.Issuer)
	}

	if conf.Listen.String() != ":4200" {
		t.Errorf("unexpected listen address: %s", conf.Listen)
	}

	if time.Duration(conf.Expire.Code) != 5*time.Minute {
		t.Errorf("unexpected code Expire: %d", conf.Expire.Code)
	}

	if time.Duration(conf.Expire.Token) != 42*24*time.Hour {
		t.Errorf("unexpected token Expire: %d", conf.Expire.Token)
	}

	if !reflect.DeepEqual(conf.Scopes, config.DefaultScopes) {
		t.Errorf("unexpected scopes: %#v", conf.Scopes)
	}

	if conf.LDAP.User != "someone" {
		t.Errorf("unexpected LDAP user: %s", conf.LDAP.User)
	}

	if conf.LDAP.Password != "secure" {
		t.Errorf("unexpected LDAP password: %s", conf.LDAP.Password)
	}

	if len(conf.Clients) != 1 {
		t.Errorf("unexpected number of clients: %#v", conf.Clients)
	} else {
		for k, v := range conf.Clients {
			if k != "test" {
				t.Errorf("unexpected client id: %s", k)
			}
			if v.Name != "test" {
				t.Errorf("unexpected client name: %s", v.Name)
			}
		}
	}

	raw = strings.NewReader(`
[ldap]
server = "ldap://someone:secure@ldap.example.com"
user = "anotherone"
password = "secret"
`)
	if err := conf.ReadReader(raw); err != nil {
		t.Fatalf("failed to load config: %s", err)
	}

	if conf.LDAP.User != "anotherone" {
		t.Errorf("unexpected LDAP user: %s", conf.LDAP.User)
	}

	if conf.LDAP.Password != "secret" {
		t.Errorf("unexpected LDAP password: %s", conf.LDAP.Password)
	}
}

func TestConfigExampleLoadable(t *testing.T) {
	conf := &config.Config{}

	if err := conf.Load("../config.example.toml", nil); err != nil {
		t.Errorf("failed to load example config: %s", err)
	}
}

func TestConfig_EndpointPaths(t *testing.T) {
	conf := config.Config{
		Issuer: &config.URL{Scheme: "https", Host: "test.example.com", Path: "/path/to"},
		Endpoints: config.EndpointConfig{
			Authz:    "/login",
			Token:    "/login/token",
			Userinfo: "/userinfo",
			Jwks:     "/jwks",
		},
	}

	endpoints := conf.EndpointPaths()

	if endpoints.OpenIDConfiguration != "/path/to/.well-known/openid-configuration" {
		t.Errorf("unexpected token endpoint: %s", endpoints.OpenIDConfiguration)
	}

	if endpoints.Authz != "/path/to/login" {
		t.Errorf("unexpected authz endpoint: %s", endpoints.Authz)
	}

	if endpoints.Token != "/path/to/login/token" {
		t.Errorf("unexpected token endpoint: %s", endpoints.Token)
	}

	if endpoints.Userinfo != "/path/to/userinfo" {
		t.Errorf("unexpected userinfo endpoint: %s", endpoints.Userinfo)
	}

	if endpoints.Jwks != "/path/to/jwks" {
		t.Errorf("unexpected jwks endpoint: %s", endpoints.Jwks)
	}
}

func TestConfig_OpenIDConfiguration(t *testing.T) {
	conf := config.Config{
		Issuer: &config.URL{Scheme: "https", Host: "test.example.com", Path: "/path/to"},
		Endpoints: config.EndpointConfig{
			Authz:    "/login",
			Token:    "/login/token",
			Userinfo: "/userinfo",
			Jwks:     "/jwks",
		},
	}

	oidconfig := conf.OpenIDConfiguration()

	if oidconfig.Issuer != "https://test.example.com/path/to" {
		t.Errorf("unexpected issuer: %s", oidconfig.Issuer)
	}

	if oidconfig.TokenEndpoint != "https://test.example.com/path/to/login/token" {
		t.Errorf("unexpected issuer: %s", oidconfig.TokenEndpoint)
	}
}
