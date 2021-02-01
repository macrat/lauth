module github.com/macrat/ldapin

go 1.15

require (
	github.com/NYTimes/gziphandler v1.1.1
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.6.3
	github.com/go-ldap/ldap/v3 v3.2.4
	github.com/gobwas/glob v0.2.3
	github.com/google/uuid v1.2.0
	github.com/mitchellh/mapstructure v1.1.2
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/prometheus/client_golang v1.9.0
	github.com/rakyll/statik v0.1.7
	github.com/rs/zerolog v1.20.0
	github.com/spf13/cobra v0.0.3
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/tdewolff/minify/v2 v2.9.11
	github.com/xhit/go-str2duration/v2 v2.0.0
	golang.org/x/crypto v0.0.0-20201217014255-9d1352758620
	golang.org/x/net v0.0.0-20200822124328-c89045814202
	golang.org/x/oauth2 v0.0.0-20210113205817-d3ed898aa8a3
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/macrat/ldapin/api => ./api

replace github.com/macrat/ldapin/config => ./config

replace github.com/macrat/ldapin/ldap => ./ldap

replace github.com/macrat/ldapin/page => ./page

replace github.com/macrat/ldapin/page/statik => ./page/statik

replace github.com/macrat/ldapin/testutil => ./testutil

replace github.com/macrat/ldapin/token => ./token
