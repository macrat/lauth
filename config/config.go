package config

import (
	"encoding"
	"encoding/json"
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
	Claim     string `json:"claim"          yaml:"claim"          toml:"claim"`
	Attribute string `json:"attribute"      yaml:"attribute"      toml:"attribute"`
	Type      string `json:"type,omitempty" yaml:"type,omitempty" toml:"type,omitempty"`
}

type ScopeConfig map[string][]ClaimConfig

type EndpointConfig struct {
	Authz    string `json:"authorization" yaml:"authorization" toml:"authorization" flag:"authz-endpoint"`
	Token    string `json:"token"         yaml:"token"         toml:"token"         flag:"token-endpoint"`
	Userinfo string `json:"userinfo"      yaml:"userinfo"      toml:"userinfo"      flag:"userinfo-endpoint"`
	Jwks     string `json:"jwks"          yaml:"jwks"          toml:"jwks"          flag:"jwks-uri"`
	Logout   string `json:"logout"        yaml:"logout"        toml:"logout"        flag:"logout-endpoint"`
}

type ExpireConfig struct {
	Login   Duration `json:"login"   yaml:"login"   toml:"login"   flag:"login-expire"`
	Code    Duration `json:"code"    yaml:"code"    toml:"code"    flag:"code-expire"`
	Token   Duration `json:"token"   yaml:"token"   toml:"token"   flag:"token-expire"`
	Refresh Duration `json:"refresh" yaml:"refresh" toml:"refresh" flag:"refresh-expire"`
	SSO     Duration `json:"sso"     yaml:"sso"     toml:"sso"     flag:"sso-expire"`
}

type ClientConfig map[string]struct {
	Secret      string     `json:"secret"       yaml:"secret"       toml:"secret"`
	RedirectURI PatternSet `json:"redirect_uri" yaml:"redirect_uri" toml:"redirect_uri"`
}

type MetricsConfig struct {
	Path     string `json:"path"               yaml:"path"               toml:"path"               flag:"metrics-path"`
	Username string `json:"username,omitempty" yaml:"username,omitempty" toml:"username,omitempty" flag:"metrics-username"`
	Password string `json:"password,omitempty" yaml:"password,omitempty" toml:"password,omitempty" flag:"metrics-password"`
}

type TLSConfig struct {
	Auto bool   `json:"auto,omitempty" yaml:"auto,omitempty" toml:"auto,omitempty" flag:"tls-auto"`
	Cert string `json:"cert,omitempty" yaml:"cert,omitempty" toml:"cert,omitempty" flag:"tls-cert"`
	Key  string `json:"key,omitempty"  yaml:"key,omitempty"  toml:"key,omitempty"  flag:"tls-key"`
}

type LDAPConfig struct {
	Server      *URL   `json:"server"       yaml:"server"       toml:"server"       flag:"ldap"`
	User        string `json:"user"         yaml:"user"         toml:"user"         flag:"ldap-user"`
	Password    string `json:"password"     yaml:"password"     toml:"password"     flag:"ldap-password"`
	BaseDN      string `json:"base_dn"      yaml:"base_dn"      toml:"base_dn"      flag:"ldap-base-dn"`
	IDAttribute string `json:"id_attribute" yaml:"id_attribute" toml:"id_attribute" flag:"ldap-id-attribute"`
	DisableTLS  bool   `json:"disable_tls"  yaml:"disable_tls"  toml:"disable_tls"  flag:"ldap-disable-tls"`
}

type TemplateConfig struct {
	LoginPage  string `json:"login_page,omitempty"  yaml:"login_page,omitempty"  toml:"login_page,omitempty"  flag:"login-page"`
	LogoutPage string `json:"logout_page,omitempty" yaml:"logout_page,omitempty" toml:"logout_page,omitempty" flag:"logout-page"`
	ErrorPage  string `json:"error_page,omitempty"  yaml:"error_page,omitempty"  toml:"error_page,omitempty"  flag:"error-page"`
}

type Config struct {
	Issuer            *URL           `json:"issuer"              yaml:"issuer"              toml:"issuer"             flag:"issuer"`
	Listen            *TCPAddr       `json:"listen,omitempty"    yaml:"listen,omitempty"    toml:"listen,omitempty"   flag:"listen"`
	SignKey           string         `json:"sign_key,omitempty"  yaml:"sign_key,omitempty"  toml:"sign_key,omitempty" flag:"sign-key"`
	TLS               TLSConfig      `json:"tls,omitempty"       yaml:"tls,omitempty"       toml:"tls,omitempty"`
	LDAP              LDAPConfig     `json:"ldap"                yaml:"ldap"                toml:"ldap"`
	Expire            ExpireConfig   `json:"expire"              yaml:"expire"              toml:"expire"`
	Endpoints         EndpointConfig `json:"endpoint"            yaml:"endpoint"            toml:"endpoint"`
	Scopes            ScopeConfig    `json:"scope,omitempty"     yaml:"scope,omitempty"     toml:"scope,omitempty"`
	Clients           ClientConfig   `json:"client,omitempty"    yaml:"client,omitempty"    toml:"client,omitempty"`
	Metrics           MetricsConfig  `json:"metrics"             yaml:"metrics"             toml:"metrics"`
	Templates         TemplateConfig `json:"template,omitempty"  yaml:"template,omitempty"  toml:"template,omitempty"`
	DisableClientAuth bool           `json:"disable_client_auth" yaml:"disable_client_auth" toml:"disable_client_auth" flag:"disable-client-auth"`
	AllowImplicitFlow bool           `json:"allow_implicit_flow" yaml:"allow_implicit_flow" toml:"allow_implicit_flow" flag:"allow-implicit-flow"`
}

func TakeOptions(prefix string, typ reflect.Type, result map[string]string) {
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("toml"), ",")[0]
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
		m.TagName = "toml"
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

	vip.SetConfigType("toml")

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

	if c.TLS.Auto && (c.TLS.Cert != "" || c.TLS.Key != "") {
		es = append(es, errors.New("--tls-auto: Can't use both of TLS auto and TLS Key/TLS Cert."))
	}
	if c.TLS.Cert != "" && c.TLS.Key == "" {
		es = append(es, errors.New("--tls-key: TLS Key is required when set TLS Cert."))
	} else if c.TLS.Cert == "" && c.TLS.Key != "" {
		es = append(es, errors.New("--tls-cert: TLS Cert is required when set TLS Key."))
	}
	if (c.TLS.Cert != "" || c.TLS.Key != "" || c.TLS.Auto) && c.Issuer.Scheme != "https" {
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
	Logout              string
}

func (c *Config) EndpointPaths() ResolvedEndpointPaths {
	return ResolvedEndpointPaths{
		OpenIDConfiguration: path.Join(c.Issuer.Path, "/.well-known/openid-configuration"),
		Authz:               path.Join(c.Issuer.Path, c.Endpoints.Authz),
		Token:               path.Join(c.Issuer.Path, c.Endpoints.Token),
		Userinfo:            path.Join(c.Issuer.Path, c.Endpoints.Userinfo),
		Jwks:                path.Join(c.Issuer.Path, c.Endpoints.Jwks),
		Logout:              path.Join(c.Issuer.Path, c.Endpoints.Logout),
	}
}

type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksEndpoint                      string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
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
		EndSessionEndpoint:                issuer + path.Join("/", c.Endpoints.Logout),
		ScopesSupported:                   append(c.Scopes.ScopeNames(), "openid"),
		ResponseTypesSupported:            responseTypes,
		ResponseModesSupported:            []string{"query", "fragment"},
		GrantTypesSupported:               []string{"authorization_code", "implicit", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
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

func (c *Config) AsJSON() (string, error) {
	t, err := json.MarshalIndent(*c, "  ", "  ")
	if err != nil {
		return "", err
	}
	return string(t), nil
}
