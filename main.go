package main

import (
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/gin-gonic/gin"
	"github.com/xhit/go-str2duration/v2"
)

var (
	app = kingpin.New("Ldapin", "The simple OpenID Provider for LDAP like a ActiveDirectory.")

	Issuer     = app.Flag("issuer", "Issuer URL.").Envar("LDAPIN_ISSUER").Default("http://localhost:8000").URL()
	Listen     = app.Flag("listen", "Listen address and port. In default, use same port as Issuer URL.").Envar("LDAPIN_LISTEN").TCP()
	PrivateKey = app.Flag("private-key", "RSA private key for signing to token. If omit this, automate generate key for one time use.").Envar("LDAPIN_PRIVATE_KEY").PlaceHolder("FILE").File()

	BasePath         = app.Flag("base-path", "Path prefix for endpoints.").Envar("LDAPIN_BASE_PATH").Default("/").String()
	AuthnEndpoint    = app.Flag("authn-endpoint", "Path to authorization endpoint.").Envar("LDAPIN_AUTHN_ENDPOINT").Default("/login").String()
	TokenEndpoint    = app.Flag("token-endpoint", "Path to token endpoint.").Envar("LDAPIN_TOKEN_ENDPOINT").Default("/login/token").String()
	UserinfoEndpoint = app.Flag("userinfo-endpoint", "Path to userinfo endpoint.").Envar("LDAPIN_USERINFO_ENDPOINT").Default("/login/userinfo").String()
	JwksEndpoint     = app.Flag("jwks-uri", "Path to jwks uri.").Envar("LDAPIN_JWKS_URI").Default("/login/certs").String()

	CodeTTL  = app.Flag("code-ttl", "TTL for code.").Envar("LDAPIN_CODE_TTL").Default("10m").String()
	TokenTTL = app.Flag("token-ttl", "TTL for access_token and id_token.").Envar("LDAPIN_TOKEN_TTL").Default("14d").String()

	LdapAddress     = app.Flag("ldap", "URL of LDAP server like \"ldap://USER_DN:PASSWORD@ldap.example.com\".").Envar("LDAP_ADDRESS").PlaceHolder("ADDRESS").Required().URL()
	LdapBaseDN      = app.Flag("ldap-base-dn", "The base DN for search user account in LDAP like \"OU=somewhere,DC=example,DC=local\".").Envar("LDAP_BASE_DN").PlaceHolder("DN").Required().String() // TODO: make it automate set same OU as bind user if omit.
	LdapIDAttribute = app.Flag("ldap-id-attribute", "ID attribute name in LDAP.").Envar("LDAP_ID_ATTRIBUTE").Default("sAMAccountName").String()

	LoginPage = app.Flag("login-page", "Templte file for login page.").Envar("LDAPIN_LOGIN_PAGE").PlaceHolder("FILE").File()
	ErrorPage = app.Flag("error-page", "Templte file for error page.").Envar("LDAPIN_ERROR_PAGE").PlaceHolder("FILE").File()

	// TODO: implement configuration file.
	//ConfigFile = app.Flag("config", "Path to configuration file.").Envar("LDAPIN_CONFIG").File()

	Verbose = app.Flag("verbose", "Enable debug mode.").Envar("LDAP_VERBOSE").Bool()
)

func DecideListenAddress(issuer *url.URL, listen *net.TCPAddr) string {
	if listen != nil {
		return listen.String()
	}

	if issuer.Port() != "" {
		return fmt.Sprintf(":%s", issuer.Port())
	}

	if issuer.Scheme == "https" {
		return ":443"
	}
	return ":80"
}

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))

	codeExpiresIn, err := str2duration.ParseDuration(*CodeTTL)
	app.FatalIfError(err, "--code-ttl")
	tokenExpiresIn, err := str2duration.ParseDuration(*TokenTTL)
	app.FatalIfError(err, "--token-ttl")

	if *Verbose {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	ldapUser := (*LdapAddress).User.Username()
	ldapPassword, _ := (*LdapAddress).User.Password()
	if ldapUser == "" && ldapPassword == "" {
		app.Fatalf("--ldap is must be has user and password information.")
		return
	}

	connector := SimpleLDAPConnector{
		ServerURL:   *LdapAddress,
		User:        ldapUser,
		Password:    ldapPassword,
		IDAttribute: *LdapIDAttribute,
		BaseDN:      *LdapBaseDN,
	}

	var jwt JWTManager
	if *PrivateKey != nil {
		jwt, err = NewJWTManagerFromFile(*PrivateKey)
		app.FatalIfError(err, "failed to read private key")
	} else {
		jwt, err = GenerateJWTManager()
		app.FatalIfError(err, "failed to generate private key")
	}

	api := &LdapinAPI{
		Connector:  connector,
		JWTManager: jwt,
		Config: LdapinConfig{
			Issuer:         (*Issuer).String(),
			CodeExpiresIn:  codeExpiresIn,
			TokenExpiresIn: tokenExpiresIn,
			Endpoints: EndpointConfig{
				BasePath: *BasePath,
				Authn:    *AuthnEndpoint,
				Token:    *TokenEndpoint,
				Userinfo: *UserinfoEndpoint,
				Jwks:     *JwksEndpoint,
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
		},
	}

	tmpl, err := loadPageTemplate(*LoginPage, *ErrorPage)
	app.FatalIfError(err, "failed to load template")
	router.SetHTMLTemplate(tmpl)

	api.SetRoutes(router)

	router.Run(DecideListenAddress(*Issuer, *Listen))
}
