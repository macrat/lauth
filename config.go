package main

import (
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/xhit/go-str2duration/v2"
	"gopkg.in/yaml.v2"
)

var (
	DefaultConfig = &LdapinConfig{
		Issuer: &URL{
			Scheme: "http",
			Host:   "localhost:8000",
		},
		TTL: TTLConfig{
			Code:  Duration(10 * time.Hour),
			Token: Duration(7 * 24 * time.Hour),
			SSO:   Duration(14 * 24 * time.Hour),
		},
		Endpoints: EndpointConfig{
			BasePath: "/",
			Authn:    "/login",
			Token:    "/login/token",
			Userinfo: "/login/userinfo",
			Jwks:     "/login/jwks",
		},
		Scopes: ScopeConfig{
			"profile": []ClaimConfig{
				{Claim: "name", Attribute: "displayName", Type: "string"},
				{Claim: "given_name", Attribute: "givenName", Type: "string"},
				{Claim: "family_name", Attribute: "sn", Type: "string"},
			},
			"email": []ClaimConfig{
				{Claim: "email", Attribute: "mail", Type: "string"},
			},
			"phone": []ClaimConfig{
				{Claim: "phone_number", Attribute: "telephoneNumber", Type: "string"},
			},
			"groups": []ClaimConfig{
				{Claim: "groups", Attribute: "memberOf", Type: "[]string"},
			},
		},
	}
)

type ClaimConfig struct {
	Claim     string `yaml:"claim"`
	Attribute string `yaml:"attribute"`
	Type      string `yaml:"type"`
}

type ScopeConfig map[string][]ClaimConfig

func (sc ScopeConfig) ScopeNames() []string {
	var ss []string
	for scope := range sc {
		ss = append(ss, scope)
	}
	return ss
}

func (sc ScopeConfig) AllClaims() []string {
	var claims []string
	for _, scope := range sc {
		for _, claim := range scope {
			claims = append(claims, claim.Claim)
		}
	}
	return claims
}

func (sc ScopeConfig) AttributesFor(scopes *StringSet) []string {
	var claims []string

	for _, scopeName := range scopes.List() {
		if scope, ok := sc[scopeName]; ok {
			for _, x := range scope {
				claims = append(claims, x.Attribute)
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
				claims[x.Attribute] = x
			}
		}
	}

	return claims
}

type EndpointConfig struct {
	BasePath string `yaml:"base_path"`
	Authn    string `yaml:"authorization"`
	Token    string `yaml:"token"`
	Userinfo string `yaml:"userinfo"`
	Jwks     string `yaml:"jwks"`
}

func (c *EndpointConfig) Override(patch EndpointConfig) {
	if patch.BasePath != "" {
		(*c).BasePath = patch.BasePath
	}
	if patch.Authn != "" {
		(*c).Authn = patch.Authn
	}
	if patch.Token != "" {
		(*c).Token = patch.Token
	}
	if patch.Userinfo != "" {
		(*c).Userinfo = patch.Userinfo
	}
	if patch.Jwks != "" {
		(*c).Jwks = patch.Jwks
	}
}

type Duration time.Duration

func ParseDuration(text string) (Duration, error) {
	d, err := str2duration.ParseDuration(text)
	return Duration(d), err
}

func (d Duration) String() string {
	return d.String()
}

func (d Duration) IntSeconds() int64 {
	return int64(time.Duration(d).Seconds())
}

func (d Duration) StrSeconds() string {
	return strconv.FormatInt(d.IntSeconds(), 10)
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	*d, err = ParseDuration(string(text))
	return err
}

type TTLConfig struct {
	Code  Duration `yaml:"code"`
	Token Duration `yaml:"token"`
	SSO   Duration `yaml:"sso"`
}

func (c *TTLConfig) Override(patch TTLConfig) {
	if patch.Code > 0 {
		(*c).Code = patch.Code
	}
	if patch.Token > 0 {
		(*c).Token = patch.Token
	}
	if patch.SSO > 0 {
		(*c).SSO = patch.SSO
	}
}

type URL url.URL

func (u *URL) String() string {
	return (*url.URL)(u).String()
}

func (u *URL) UnmarshalText(text []byte) error {
	parsed, err := url.Parse(string(text))
	if err != nil {
		return err
	}
	*u = URL(*parsed)
	return nil
}

func (u *URL) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

type TCPAddr net.TCPAddr

func (a *TCPAddr) String() string {
	return (*net.TCPAddr)(a).String()
}

func (a *TCPAddr) UnmarshalText(text []byte) error {
	parsed, err := net.ResolveTCPAddr("", string(text))
	if err != nil {
		return err
	}
	*a = TCPAddr(*parsed)
	return nil
}

func (a *TCPAddr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

type LdapinConfig struct {
	Issuer    *URL           `yaml:"issuer"`
	Listen    *TCPAddr       `yaml:"listen"`
	TTL       TTLConfig      `yaml:"ttl"`
	Endpoints EndpointConfig `yaml:"endpoint"`
	Scopes    ScopeConfig    `yaml:"scope"`
	//Clients   []ClientConfig `yaml:"client"`  // TODO: implement client authentication.
}

func LoadConfig(f io.Reader) (*LdapinConfig, error) {
	raw, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var conf LdapinConfig
	err = yaml.Unmarshal(raw, &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

func (c *LdapinConfig) Override(patch *LdapinConfig) {
	if patch.Issuer != nil && patch.Issuer.String() != "" {
		(*c).Issuer = patch.Issuer
	}

	(&c.TTL).Override(patch.TTL)
	(&c.Endpoints).Override(patch.Endpoints)

	if patch.Scopes != nil {
		(*c).Scopes = patch.Scopes
	}
}

func (c *LdapinConfig) OpenIDConfiguration() map[string]interface{} {
	issuer := c.Issuer.String()
	return map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + path.Join("/", c.Endpoints.BasePath, c.Endpoints.Authn),
		"token_endpoint":                        issuer + path.Join("/", c.Endpoints.BasePath, c.Endpoints.Token),
		"userinfo_endpoint":                     issuer + path.Join("/", c.Endpoints.BasePath, c.Endpoints.Userinfo),
		"jwks_uri":                              issuer + path.Join("/", c.Endpoints.BasePath, c.Endpoints.Jwks),
		"scopes_supported":                      append(c.Scopes.ScopeNames(), "openid"),
		"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"},
		"response_modes_supported":              []string{"query", "fragment"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"display_values_supported":              []string{"page"},
		"claims_supported":                      append(c.Scopes.AllClaims(), "iss", "sub", "aud", "exp", "iat", "typ", "auth_time"),
	}
}
