package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/api"
	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/ldap"
	"github.com/macrat/lauth/metrics"
	"github.com/macrat/lauth/page"
	"github.com/macrat/lauth/token"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func serve(conf *config.Config) {
	router := gin.New()
	router.Use(gin.Recovery())

	fmt.Printf("OpenID Provider \"%s\" started on %s\n", conf.Issuer, conf.Listen)
	fmt.Println()

	if debug {
		fmt.Fprintln(os.Stderr, "WARNING  Debug mode is enabled.")
		fmt.Fprintln(os.Stderr, "         Logs will include credentials or sensitive data.")
		fmt.Fprintln(os.Stderr, "")
	}

	if conf.Issuer.Scheme == "http" {
		fmt.Fprintln(os.Stderr, "DANGER  Serve OAuth2/OpenID service over no encrypted HTTP.")
		fmt.Fprintln(os.Stderr, "        An attacker can peek or rewrite user credentials, profile, or authorization.")
		fmt.Fprintln(os.Stderr, "        Please set HTTPS URL to --issuer option.")
		fmt.Fprintln(os.Stderr, "        And, you can enable TLS by --tls-cert and --tls-key options.")
		fmt.Fprintln(os.Stderr, "")
	}

	if conf.LDAP.Server.Scheme == "ldap" && conf.LDAP.DisableTLS {
		fmt.Fprintln(os.Stderr, "DANGER  Communication with LDAP server won't encryption.")
		fmt.Fprintln(os.Stderr, "        An attacker in your network can peek at user credentials or profile.")
		fmt.Fprintln(os.Stderr, "        Please consider removing --ldap-disable-tls option.")
		fmt.Fprintln(os.Stderr, "")
	}

	if len(conf.Clients) == 0 && !conf.DisableClientAuth {
		fmt.Fprintln(os.Stderr, "WARNING  No client is registered in the config file.")
		fmt.Fprintln(os.Stderr, "         So, no client can use this provider.")
		fmt.Fprintln(os.Stderr, "         Please consider register clients or use --disable-client-auth option.")
		fmt.Fprintln(os.Stderr, "")
	}

	if !conf.AllowImplicitFlow {
		fmt.Fprintln(os.Stderr, "NOTE  Implicit flow is disallowed.")
		fmt.Fprintln(os.Stderr, "      Perhaps you have to allow this if used by SPA site.")
		fmt.Fprintln(os.Stderr, "      You can allow this with --allow-implicit-flow option.")
		fmt.Fprintln(os.Stderr, "")
	}

	if debug {
		fmt.Println("---")
		confYAML, _ := conf.AsYAML()
		fmt.Print(confYAML)
		fmt.Println("---")
	}

	var tokenManager token.Manager
	if conf.SignKey != "" {
		log.Info().Msg("loading sign key")

		f, err := os.Open(conf.SignKey)
		if err != nil {
			log.Fatal().Msgf("failed to open sign key: %s", err)
		}

		tokenManager, err = token.NewManagerFromFile(f)
		if err != nil {
			log.Fatal().Msgf("failed to read sign key: %s", err)
		}
	} else {
		log.Info().Msg("generating RSA key for signing")

		var err error
		tokenManager, err = token.GenerateManager()
		if err != nil {
			log.Fatal().Msgf("failed to generate private key for sign: %s", err)
		}
	}

	log.Info().
		Str("ldap_server", conf.LDAP.Server.String()).
		Msg("connecting to LDAP server")
	connector := ldap.SimpleConnector{
		Config: &conf.LDAP,
	}
	_, err := connector.Connect()
	if err != nil {
		log.Fatal().Msgf("failed to connect LDAP server: %s", err)
	}

	api := &api.LauthAPI{
		Connector:    connector,
		TokenManager: tokenManager,
		Config:       conf,
	}

	log.Info().
		Str("login_page", conf.Templates.LoginPage).
		Str("error_page", conf.Templates.ErrorPage).
		Msg("loading HTML templates")
	tmpl, err := page.Load(conf.Templates)
	if err != nil {
		log.Fatal().Msgf("failed to load template: %s", err)
	}
	router.SetHTMLTemplate(tmpl)

	router.Use(func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("Content-Security-Policy", "frame-ancestors 'none'")
	})

	router.GET(conf.Metrics.Path, gin.WrapH(metrics.Handler(conf.Metrics.Username, conf.Metrics.Password)))

	api.SetRoutes(router)
	api.SetErrorRoutes(router)

	log.Info().Msg("ready to serve")

	server := &http.Server{
		Addr:    conf.Listen.String(),
		Handler: metrics.Middleware(HTTPCompressor(router)),
	}
	if conf.TLS.Cert != "" {
		err = server.ListenAndServeTLS(conf.TLS.Cert, conf.TLS.Key)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}
}

var (
	configFile = ""
	debug      = false
	conf       = &config.Config{}
	cmd        = &cobra.Command{
		Use:   "lauth",
		Short: "The simple OpenID Provider for LDAP like an ActiveDirectory.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			zerolog.ErrorFieldName = "error_reason"

			if debug {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
				gin.SetMode(gin.DebugMode)
			} else {
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
				gin.SetMode(gin.ReleaseMode)
			}

			err := conf.Load(configFile, cmd.Flags())
			if err != nil {
				return err
			}

			return conf.Validate()
		},
		Run: func(cmd *cobra.Command, args []string) {
			serve(conf)
		},
	}
)

func init() {
	flags := cmd.Flags()
	flags.SortFlags = false

	flags.VarP(&config.URL{Scheme: "http", Host: "localhost:8000"}, "issuer", "i", "Issuer URL.")
	flags.Var(&config.TCPAddr{}, "listen", "Listen address and port. In default, use the same port as the Issuer URL.")
	flags.StringP("sign-key", "s", "", "RSA private key for signing to token. If omit this, automate generate key for one time use.")

	flags.Bool("allow-implicit-flow", false, "Allow implicit/hybrid flow. It's may use for the SPA site or native application.")
	flags.Bool("disable-client-auth", false, "Allow use token endpoint without client authentication.")

	flags.String("tls-cert", "", "Cert file for TLS encryption.")
	flags.String("tls-key", "", "Key file for TLS encryption.")

	flags.String("authz-endpoint", "/login", "Path to authorization endpoint.")
	flags.String("token-endpoint", "/login/token", "Path to token endpoint.")
	flags.String("userinfo-endpoint", "/login/userinfo", "Path to userinfo endpoint.")
	flags.String("jwks-uri", "/login/jwks", "Path to jwks uri.")

	loginExpire := config.Duration(1 * time.Hour)
	flags.Var(&loginExpire, "login-expire", "Time limit to input username and password on the login page.")
	codeExpire := config.Duration(5 * time.Minute)
	flags.Var(&codeExpire, "code-expire", "Time limit to exchange code to access_token or id_token.")
	tokenExpire := config.Duration(24 * time.Hour)
	flags.Var(&tokenExpire, "token-expire", "Expiration duration of access_token and id_token.")
	refreshExpire := config.Duration(7 * 24 * time.Hour)
	flags.Var(&refreshExpire, "refresh-expire", "Expiration duration of refresh_token. If set 0, refresh_token will not create.")
	ssoExpire := config.Duration(14 * 24 * time.Hour)
	flags.Var(&ssoExpire, "sso-expire", "Duration for don't show login page if logged in past. If set 0, always ask the username and password to the end-user.")

	flags.VarP(&config.URL{}, "ldap", "l", "URL of LDAP server. You can include user credentials like \"ldap://USER_DN:PASSWORD@ldap.example.com\".")
	flags.String("ldap-user", "", "User DN for connecting to LDAP. You can use \"DOMAIN\\username\" style if using ActiveDirectory.")
	flags.String("ldap-password", "", "Password for connecting to LDAP.")
	flags.String("ldap-base-dn", "", "The base DN for search user account in LDAP like \"OU=somewhere,DC=example,DC=local\".")
	flags.String("ldap-id-attribute", "sAMAccountName", "ID attribute name in LDAP.")
	flags.Bool("ldap-disable-tls", false, "Disable use TLS when connecting to the LDAP server. THIS IS INSECURE.")

	flags.String("login-page", "", "Templte file for login page.")
	flags.String("error-page", "", "Templte file for error page.")

	flags.String("metrics-path", "/metrics", "Path to Prometheus metrics.")
	flags.String("metrics-username", "", "Basic auth username to access to Prometheus metrics. If omit, disable authentication.")
	flags.String("metrics-password", "", "Basic auth password to access to Prometheus metrics. If omit, disable authentication.")

	flags.StringVarP(&configFile, "config", "c", "", "Load options from YAML file.")
	flags.BoolVar(&debug, "debug", false, "Enable debug output. This is insecure for production use.")
}

func main() {
	if cmd.Execute() != nil {
		os.Exit(1)
	}
}
