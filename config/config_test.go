package config_test

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/macrat/ldapin/config"
)

func TestConfig_Override(t *testing.T) {
	conf := &config.LdapinConfig{}

	if !reflect.DeepEqual(conf, &config.LdapinConfig{}) {
		t.Errorf("expected empty but got %#v", conf)
	}

	conf.Override(&config.LdapinConfig{
		TTL: config.TTLConfig{
			Code: config.Duration(42 * time.Minute),
		},
	})
	if !reflect.DeepEqual(conf, &config.LdapinConfig{TTL: config.TTLConfig{Code: config.Duration(42 * time.Minute)}}) {
		t.Errorf("expected set code ttl but got %#v", conf)
	}

	conf.Override(config.DefaultConfig)
	if !reflect.DeepEqual(conf, config.DefaultConfig) {
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
	conf, err := config.LoadConfig(raw)
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
	f, err := os.Open("../config.example.yml")
	if err != nil {
		t.Fatalf("failed to open example config: %s", err)
	}

	_, err = config.LoadConfig(f)
	if err != nil {
		t.Errorf("failed to load example config: %s", err)
	}
}

func TestLdapinConfig_EndpointPaths(t *testing.T) {
	conf := config.LdapinConfig{
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

func TestLdapinConfig_OpenIDConfiguration(t *testing.T) {
	conf := config.LdapinConfig{
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
