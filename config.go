package main

import (
	"path"
	"time"
)

type ClaimConfig struct {
	Claim     string `toml:"claim"`
	Attribute string `toml:"attribute"`
	Type      string `toml:"type"`
}

type ScopeConfig map[string][]ClaimConfig

func (sc ScopeConfig) ScopeNames() []string {
	var ss []string
	for scope, _ := range sc {
		ss = append(ss, scope)
	}
	return ss
}

func (sc ScopeConfig) AllClaimNames() []string {
	var claims []string
	for _, scope := range sc {
		for _, claim := range scope {
			claims = append(claims, claim.Claim)
		}
	}
	return claims
}

func (sc ScopeConfig) ClaimNamesFor(scopes *StringSet) []string {
	var claims []string

	for _, scopeName := range scopes.List() {
		if scope, ok := sc[scopeName]; ok {
			for _, x := range scope {
				claims = append(claims, x.Claim)
			}
		}
	}

	return claims
}

func (sc ScopeConfig) ClaimMapFor(scopes *StringSet) map[string]ClaimConfig {
	claims := make(map[string]ClaimConfig)

	for _, scopeName := range scopes.List() {
		if scope, ok := sc[scopeName]; ok {
			for _, x := range scope {
				claims[x.Claim] = x
			}
		}
	}

	return claims
}

type EndpointConfig struct {
	Authn    string `toml:"authorization"`
	Token    string `toml:"token"`
	Userinfo string `toml:"userinfo"`
	Jwks     string `toml:"jwks"`
}

type LdapinConfig struct {
	Issuer         string         `toml:"issuer"`
	CodeExpiresIn  time.Duration  `toml:"code_ttl"`
	TokenExpiresIn time.Duration  `toml:"token_ttl"`
	Endpoints      EndpointConfig `toml:"endpoint"`
	Scopes         ScopeConfig    `toml:"scope"`
}

func (c LdapinConfig) OpenIDConfiguration() map[string]interface{} {
	return map[string]interface{}{
		"issuer":                                c.Issuer,
		"authorization_endpoint":                path.Join(c.Issuer, c.Endpoints.Authn),
		"token_endpoint":                        path.Join(c.Issuer, c.Endpoints.Token),
		"userinfo_endpoint":                     path.Join(c.Issuer, c.Endpoints.Userinfo),
		"jwks_uri":                              path.Join(c.Issuer, c.Endpoints.Jwks),
		"scopes_supported":                      append(c.Scopes.ScopeNames(), "openid"),
		"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"},
		"response_modes_supported":              []string{"query", "fragment"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"display_values_supported":              []string{"page"},
		"claims_supported":                      append(c.Scopes.AllClaimNames(), "iss", "sub", "aud", "exp", "iat", "typ", "auth_time"),
	}
}
