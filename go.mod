module github.com/macrat/ldapin

go 1.15

require (
	github.com/NYTimes/gziphandler v1.1.1
	github.com/alecthomas/kingpin v2.2.6+incompatible
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20201120081800-1786d5ef83d4 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.6.3
	github.com/go-ldap/ldap v3.0.3+incompatible
	github.com/google/uuid v1.2.0
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/rakyll/statik v0.1.7
	github.com/tdewolff/minify/v2 v2.9.11
	github.com/xhit/go-str2duration/v2 v2.0.0
	golang.org/x/crypto v0.0.0-20201217014255-9d1352758620 // indirect
	golang.org/x/net v0.0.0-20200822124328-c89045814202
	golang.org/x/oauth2 v0.0.0-20210113205817-d3ed898aa8a3
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v2 v2.2.8
)

replace github.com/macrat/ldapin/api => ./api

replace github.com/macrat/ldapin/config => ./config

replace github.com/macrat/ldapin/ldap => ./ldap

replace github.com/macrat/ldapin/page => ./page

replace github.com/macrat/ldapin/page/statik => ./page/statik

replace github.com/macrat/ldapin/testutil => ./testutil

replace github.com/macrat/ldapin/token => ./token
