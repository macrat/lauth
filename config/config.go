package config

import (
	"io"
	"io/ioutil"
	"path"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	DefaultConfig = &LdapinConfig{
		Issuer: &URL{
			Scheme: "http",
			Host:   "localhost:8000",
		},
		TTL: TTLConfig{
			Login:   NewDuration(1 * time.Hour),
			Code:    NewDuration(5 * time.Minute),
			Token:   NewDuration(1 * 24 * time.Hour),
			Refresh: NewDuration(7 * 24 * time.Hour),
			SSO:     NewDuration(14 * 24 * time.Hour),
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
		Metrics: MetricsConfig{
			Path: "/metrics",
		},
		DisableClientAuth: false,
		AllowImplicitFlow: false,
	}
)

type ClaimConfig struct {
	Claim     string `yaml:"claim"`
	Attribute string `yaml:"attribute"`
	Type      string `yaml:"type"`
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

type TTLConfig struct {
	Login   *Duration `yaml:"login"`
	Code    *Duration `yaml:"code"`
	Token   *Duration `yaml:"token"`
	Refresh *Duration `yaml:"refresh"`
	SSO     *Duration `yaml:"sso"`
}

func (c *TTLConfig) Override(patch TTLConfig) {
	if patch.Login != nil {
		(*c).Login = patch.Login
	}
	if patch.Code != nil {
		(*c).Code = patch.Code
	}
	if patch.Token != nil {
		(*c).Token = patch.Token
	}
	if patch.Refresh != nil {
		(*c).Refresh = patch.Refresh
	}
	if patch.SSO != nil {
		(*c).SSO = patch.SSO
	}
}

type ClientConfig map[string]struct {
	Secret      string     `yaml:"secret"`
	RedirectURI PatternSet `yaml:"redirect_uri"`
}

type MetricsConfig struct {
	Path     string `yaml:"path"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (c *MetricsConfig) Override(patch MetricsConfig) {
	if patch.Path != "" {
		(*c).Path = patch.Path
	}
	if patch.Username != "" {
		(*c).Username = patch.Username
	}
	if patch.Password != "" {
		(*c).Password = patch.Password
	}
}

type LdapinConfig struct {
	Issuer            *URL           `yaml:"issuer"`
	Listen            *TCPAddr       `yaml:"listen"`
	TTL               TTLConfig      `yaml:"ttl"`
	Endpoints         EndpointConfig `yaml:"endpoint"`
	Scopes            ScopeConfig    `yaml:"scope"`
	Clients           ClientConfig   `yaml:"client"`
	Metrics           MetricsConfig  `yaml:"metrics"`
	DisableClientAuth bool           `yaml:"disable_client_auth"`
	AllowImplicitFlow bool           `yaml:"allow_implicit_flow"`
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
	(&c.Metrics).Override(patch.Metrics)

	if patch.Scopes != nil {
		(*c).Scopes = patch.Scopes
	}

	if patch.Clients != nil {
		(*c).Clients = patch.Clients
	}

	if patch.DisableClientAuth {
		(*c).DisableClientAuth = patch.DisableClientAuth
	}

	if patch.AllowImplicitFlow {
		(*c).AllowImplicitFlow = patch.AllowImplicitFlow
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
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksEndpoint                      string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	DisplayValuesSupported            []string `json:"display_values_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
}

func (c *LdapinConfig) OpenIDConfiguration() OpenIDConfiguration {
	issuer := c.Issuer.String()

	responseTypes := []string{"code"}
	if c.AllowImplicitFlow {
		responseTypes = []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		}
	}

	return OpenIDConfiguration{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + path.Join("/", c.Endpoints.Authz),
		TokenEndpoint:                     issuer + path.Join("/", c.Endpoints.Token),
		UserinfoEndpoint:                  issuer + path.Join("/", c.Endpoints.Userinfo),
		JwksEndpoint:                      issuer + path.Join("/", c.Endpoints.Jwks),
		ScopesSupported:                   append(c.Scopes.ScopeNames(), "openid"),
		ResponseTypesSupported:            responseTypes,
		ResponseModesSupported:            []string{"query", "fragment"},
		GrantTypesSupported:               []string{"authorization_code", "implicit", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_pot", "client_secret_basic"},
		DisplayValuesSupported:            []string{"page"},
		ClaimsSupported: append(
			c.Scopes.AllClaims(),
			"iss",
			"sub",
			"aud",
			"exp",
			"iat",
			"typ",
			"auth_time",
			"nonce",
			"c_hash",
			"at_hash",
		),
		RequestURIParameterSupported: false,
	}
}
