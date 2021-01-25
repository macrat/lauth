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
			Authz:    "/login",
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
	Authz    string `yaml:"authorization"`
	Token    string `yaml:"token"`
	Userinfo string `yaml:"userinfo"`
	Jwks     string `yaml:"jwks"`
}

func (c *EndpointConfig) Override(patch EndpointConfig) {
	if patch.Authz != "" {
		(*c).Authz = patch.Authz
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

type ResolvedEndpointPaths struct {
	OpenIDConfiguration string
	Authz               string
	Token               string
	Userinfo            string
	Jwks                string
}

func (c *LdapinConfig) EndpointPaths() ResolvedEndpointPaths {
	return ResolvedEndpointPaths{
		OpenIDConfiguration: path.Join(c.Issuer.Path, "/.well-known/openid-configuration"),
		Authz:               path.Join(c.Issuer.Path, c.Endpoints.Authz),
		Token:               path.Join(c.Issuer.Path, c.Endpoints.Token),
		Userinfo:            path.Join(c.Issuer.Path, c.Endpoints.Userinfo),
		Jwks:                path.Join(c.Issuer.Path, c.Endpoints.Jwks),
	}
}

type OpenIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksEndpoint                     string   `json:"jwks_uri"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ResponseModesSupported           []string `json:"response_modes_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	DisplayValuesSupported           []string `json:"display_values_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

func (c *LdapinConfig) OpenIDConfiguration() OpenIDConfiguration {
	issuer := c.Issuer.String()

	return OpenIDConfiguration{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + path.Join("/", c.Endpoints.Authz),
		TokenEndpoint:         issuer + path.Join("/", c.Endpoints.Token),
		UserinfoEndpoint:      issuer + path.Join("/", c.Endpoints.Userinfo),
		JwksEndpoint:          issuer + path.Join("/", c.Endpoints.Jwks),
		ScopesSupported:       append(c.Scopes.ScopeNames(), "openid"),
		ResponseTypesSupported: []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},
		ResponseModesSupported:           []string{"query", "fragment"},
		GrantTypesSupported:              []string{"authorization_code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		DisplayValuesSupported:           []string{"page"},
		ClaimsSupported: append(
			c.Scopes.AllClaims(),
			"iss",
			"sub",
			"aud",
			"exp",
			"iat",
			"typ",
			"auth_time",
		),
	}
}
