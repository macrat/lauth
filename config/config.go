package config

import (
	"encoding"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var (
	DefaultScopes = ScopeConfig{
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
	}
)

type ClaimConfig struct {
	Claim     string `yaml:"claim"`
	Attribute string `yaml:"attribute"`
	Type      string `yaml:"type,omitempty"`
}

type ScopeConfig map[string][]ClaimConfig

type EndpointConfig struct {
	Authz    string `yaml:"authorization" flag:"authz-endpoint"`
	Token    string `yaml:"token"         flag:"token-endpoint"`
	Userinfo string `yaml:"userinfo"      flag:"userinfo-endpoint"`
	Jwks     string `yaml:"jwks"          flag:"jwks-uri"`
}

type ExpireConfig struct {
	Login   Duration `yaml:"login"   flag:"login-expire"`
	Code    Duration `yaml:"code"    flag:"code-expire"`
	Token   Duration `yaml:"token"   flag:"token-expire"`
	Refresh Duration `yaml:"refresh" flag:"refresh-expire"`
	SSO     Duration `yaml:"sso"     flag:"sso-expire"`
}

type ClientConfig map[string]struct {
	Secret      string     `yaml:"secret"`
	RedirectURI PatternSet `yaml:"redirect_uri"`
}

type MetricsConfig struct {
	Path     string `yaml:"path"               flag:"metrics-path"`
	Username string `yaml:"username,omitempty" flag:"metrics-username"`
	Password string `yaml:"password,omitempty" flag:"metrics-password"`
}

type TLSConfig struct {
	Cert string `yaml:"cert,omitempty" flag:"tls-cert"`
	Key  string `yaml:"key,omitempty"  flag:"tls-key"`
}

type LDAPConfig struct {
	Server      *URL   `yaml:"server"       flag:"ldap"`
	User        string `yaml:"user"         flag:"ldap-user"`
	Password    string `yaml:"password"     flag:"ldap-password"`
	BaseDN      string `yaml:"base_dn"      flag:"ldap-base-dn"`
	IDAttribute string `yaml:"id_attribute" flag:"ldap-id-attribute"`
	DisableTLS  bool   `yaml:"disable_tls"  flag:"ldap-disable-tls"`
}

type TemplateConfig struct {
	LoginPage string `yaml:"login_page,omitempty" flag:"login-page"`
	ErrorPage string `yaml:"error_page,omitempty" flag:"error-page"`
}

type Config struct {
	Issuer            *URL           `yaml:"issuer"             flag:"issuer"`
	Listen            *TCPAddr       `yaml:"listen,omitempty"   flag:"listen"`
	SignKey           string         `yaml:"sign_key,omitempty" flag:"sign-key"`
	TLS               TLSConfig      `yaml:"tls,omitempty"`
	LDAP              LDAPConfig     `yaml:"ldap"`
	Expire            ExpireConfig   `yaml:"expire"`
	Endpoints         EndpointConfig `yaml:"endpoint"`
	Scopes            ScopeConfig    `yaml:"scope,omitempty"`
	Clients           ClientConfig   `yaml:"client,omitempty"`
	Metrics           MetricsConfig  `yaml:"metrics"`
	Templates         TemplateConfig `yaml:"template,omitempty"`
	DisableClientAuth bool           `yaml:"disable_client_auth" flag:"disable-client-auth"`
	AllowImplicitFlow bool           `yaml:"allow_implicit_flow" flag:"allow-implicit-flow"`
}

func TakeOptions(prefix string, typ reflect.Type, result map[string]string) {
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		flag := f.Tag.Get("flag")

		if name != "" {
			key := prefix + name

			if flag != "" {
				result[key] = flag
			} else if f.Type.Kind() == reflect.Struct {
				TakeOptions(key+".", f.Type, result)
			}
		}
	}
}

func BindFlags(vip *viper.Viper, flags *pflag.FlagSet) {
	options := map[string]string{}
	TakeOptions("", reflect.TypeOf(Config{}), options)
	for k, v := range options {
		f := flags.Lookup(v)
		if f == nil {
			panic(fmt.Sprintf("flag %s is not found", v))
		}
		vip.BindPFlag(k, f)
	}
}

func (c *Config) unmarshal(vip *viper.Viper) error {
	err := vip.Unmarshal(c, func(m *mapstructure.DecoderConfig) {
		m.TagName = "yaml"
		m.DecodeHook = func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
			if f.Kind() != reflect.String {
				return data, nil
			}
			result := reflect.New(t).Interface()
			unmarshaller, ok := result.(encoding.TextUnmarshaler)
			if !ok {
				return data, nil
			}
			if err := unmarshaller.UnmarshalText([]byte(data.(string))); err != nil {
				return nil, err
			}
			return result, nil
		}
	})
	if err != nil {
		return err
	}

	c.Listen = DecideListenAddress(c.Issuer, c.Listen)

	if c.Scopes == nil {
		c.Scopes = DefaultScopes
	}

	if c.LDAP.Server != nil {
		if c.LDAP.User == "" {
			c.LDAP.User = c.LDAP.Server.User.Username()
		}
		if c.LDAP.Password == "" {
			c.LDAP.Password, _ = c.LDAP.Server.User.Password()
		}
		c.LDAP.Server.User = nil
	}

	if c.LDAP.BaseDN == "" {
		c.LDAP.BaseDN, _ = GetDCByDN(c.LDAP.User)
	}

	return nil
}

type EnvReplacer struct{}

func (r EnvReplacer) Replace(s string) string {
	return strings.ReplaceAll(s, ".", "_")
}

func (c *Config) Load(file string, flags *pflag.FlagSet) error {
	var replacer EnvReplacer
	vip := viper.NewWithOptions(viper.EnvKeyReplacer(replacer))

	if flags != nil {
		BindFlags(vip, flags)
	}
	vip.SetEnvPrefix("LAUTH")
	vip.AutomaticEnv()

	vip.SetConfigType("yaml")

	if file == "" {
		file = os.Getenv("LAUTH_CONFIG")
	}

	if file != "" {
		vip.SetConfigFile(file)
		if err := vip.ReadInConfig(); err != nil {
			return err
		}
	}

	return c.unmarshal(vip)
}

func (c *Config) ReadReader(config io.Reader) error {
	vip := viper.New()

	vip.SetConfigType("yaml")

	if err := vip.ReadConfig(config); err != nil {
		return err
	}

	return c.unmarshal(vip)
}

func (c *Config) Validate() error {
	var es ParseErrorSet

	if c.Issuer.String() == "" {
		es = append(es, errors.New("--issuer: Issuer URL is required."))
	} else if !(*url.URL)(c.Issuer).IsAbs() {
		es = append(es, errors.New("--issuer: Issuer URL must be absolute URL."))
	}

	if c.TLS.Cert != "" && c.TLS.Key == "" {
		es = append(es, errors.New("--tls-key: TLS Key is required when set TLS Cert."))
	} else if c.TLS.Cert == "" && c.TLS.Key != "" {
		es = append(es, errors.New("--tls-cert: TLS Cert is required when set TLS Key."))
	}
	if c.TLS.Cert != "" && c.TLS.Key != "" && c.Issuer.Scheme != "https" {
		es = append(es, errors.New("--issuer: Please set https URL for Issuer URL when use TLS."))
	}

	if c.LDAP.Server.String() == "" {
		es = append(es, errors.New("--ldap: LDAP Server address is required."))
	}
	if c.LDAP.User == "" {
		es = append(es, errors.New("--ldap-user: LDAP User is required."))
	}
	if c.LDAP.Password == "" {
		es = append(es, errors.New("--ldap-password: LDAP Password is required."))
	}
	if c.LDAP.BaseDN == "" {
		es = append(es, errors.New("--ldap-base-dn: LDAP Base DN is required if using user that non DN style."))
	}

	if c.Expire.Login <= 0 {
		es = append(es, errors.New("--login-expire: Expiration of Login can't set 0 or less."))
	}
	if c.Expire.Code <= 0 {
		es = append(es, errors.New("--code-expire: Expiration of Code can't set 0 or less."))
	}
	if c.Expire.Token <= 0 {
		es = append(es, errors.New("--token-expire: Expiration of Token can't set 0 or less."))
	}

	if c.Metrics.Path == "" {
		es = append(es, errors.New("--metrics-path: Metrics Path can't set empty."))
	}
	if c.Metrics.Username != "" && c.Metrics.Password == "" {
		es = append(es, errors.New("--metrics-username: Metrics Username is required when set Metrics Password."))
	} else if c.Metrics.Username == "" && c.Metrics.Password != "" {
		es = append(es, errors.New("--metrics-password: Metrics Password is required when set Metrics Username."))
	}

	if len(es) > 0 {
		return es
	}
	return nil
}

type ResolvedEndpointPaths struct {
	OpenIDConfiguration string
	Authz               string
	Token               string
	Userinfo            string
	Jwks                string
}

func (c *Config) EndpointPaths() ResolvedEndpointPaths {
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

func (c *Config) OpenIDConfiguration() OpenIDConfiguration {
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

func (c *Config) AsYAML() (string, error) {
	y, err := yaml.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(y), nil
}
