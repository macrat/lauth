Lauth
=====

![Test and Build](https://github.com/macrat/lauth/workflows/Test%20and%20Build/badge.svg)
[![codecov](https://codecov.io/gh/macrat/lauth/branch/main/graph/badge.svg)](https://codecov.io/gh/macrat/lauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/macrat/lauth)](https://goreportcard.com/report/github.com/macrat/lauth)
[![Docker Hub](https://img.shields.io/badge/container-Docker%20Hub-blue.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/macrat/lauth)
[![GitHub Container Registry](https://img.shields.io/badge/container-ghcr.io-blue.svg?logo=docker&logoColor=white)](https://github.com/users/macrat/packages/container/package/lauth)
[![License](https://img.shields.io/github/license/macrat/lauth)](https://github.com/macrat/lauth/blob/master/LICENSE)

The simple OpenID Provider for LDAP like a Microsoft ActiveDirectory(AD).

![Lauth can translate LDAP and OAuth2/OpenID Connect](./images/lauth.jpg)


## Compatibility

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth2 (RFC6749)](https://tools.ietf.org/html/rfc6749)
- LDAP v3 (use [go-ldap](https://github.com/go-ldap/ldap))


## Installation

### Use on Docker

``` shell
$ docker run macrat/lauth:latest --version
lauth version 1.0.0
```

### Build by source

``` shell
$ go get github.com/macrat/lauth

$ lauth --version
lauth version 1.0.0
```


## Usage

First, Generate a config file.

``` shell
$ lauth gen-client your-client-name > config.yml
```

Then, start the server.

``` shell
$ lauth \
  --ldap ldap://ldap.example.com \
  --ldap-user "CN=username,OU=somewhere,DC=example,DC=local" \
  --ldap-password ${LDAP_USER_PASSWORD} \
  --config config.yml
```

Finally, use it.

- authorization endpoint:
  http://localhost:8000/login

- token endpoint:
  http://localhost:8000/login/token

- userinfo endpoint:
  http://localhost:8000/login/userinfo

- jwks endpoint:
  http://localhost:8000/login/jwks

- discovery endpoint:
  http://localhost:8000/.well-known/openid-configuration

### For production

In the production use-case, please add those options.

- `--issuer`: External URL of the server.
- `--sign-key`: RSA private key for signing to the token.
- `--tls-cert` and `--tls-key`: TLS encryption key files.
- `--metrics-username` and `--metrics-password`: Credentials for protect metrics page. (metrics page perhaps interesting hint for an attacker)


## Customize

### Page design

This is default page design:

![default design of login page and error page](./images/default_design.jpg)

If you want to customize the design, you can use `--login-page` and `--error-page`.
Templates using [html/template](https://golang.org/pkg/html/template/) libraries format.

Please see also the default page templates:

- [login page](./page/html/login.tmpl)
- [error page](./page/html/error.tmpl)

### ID attribute

In default, Lauth uses `sAMAccountName` as the username.
That is the logon ID of Microsoft ActiveDirectory.

Please use `--ldap-id-attribute` option if you want to use another attribute as the username.

``` shell
$ lauth --ldap-id-attribute mail  # login with e-mail
```

Or, you can use a config file.

``` shell
$ cat <<EOS > config.yml
ldap:
  id_attribute: mail
EOS

$ lauth --config config.yml
```

### Scope and Claims

You can change scope and claims for `id_token` and userinfo in the config file.

In default, set claims for Microsoft ActiveDirectory.

``` yaml
scope:
  profile:
    - claim: name
      attribute: displayName
    - claim: given_name
      attribute: givenName
    - claim: family_name
      attribute: sn

  email:
    - claim: email
      attribute: mail

  phone:
    - claim: phone_number
      attribute: telephoneNumber

  groups:
    - claim: groups
      attribute: memberOf
      type: '[]string'
```


## Options

### server command

``` shell
$ lauth [OPTIONS]
```

|command line           |config file          |environment variable       |default value              |description|
|-----------------------|---------------------|---------------------------|---------------------------|-----------|
|`--issuer`             |`issuer`             |`LAUTH_ISSUER`             |`http://localhost:8000`    |Issuer URL.|
|`--listen`             |`listen`             |`LAUTH_LISTEN`             |same port as the Issuer URL|Listen address and port.|
|`--sign-key`           |`sign_key`           |`LAUTH_SIGN_KEY`           |generate random key        |RSA private key for signing to token.|
|`--allow-implicit-flow`|`allow_implicit_flow`|`LAUTH_ALLOW_IMPLICIT_FLOW`|                           |Allow implicit/hybrid flow.<br />It's may use for the SPA site or native application.|
|`--disable-client-auth`|`disable_client_auth`|`LAUTH_DISABLE_CLIENT_AUTH`|                           |Allow use token endpoint without client authentication.|
|`--tls-cert`           |`tls.cert`           |`LAUTH_TLS_CERT`           |                           |Cert file for TLS encryption.|
|`--tls-key`            |`tls.key`            |`LAUTH_TLS_KEY`            |                           |Key file for TLS encryption.|
|`--authz-endpoint`     |`endpoint.authz`     |`LAUTH_ENDPOINT_AUTHZ`     |`/login`                   |Path to authorization endpoint.|
|`--token-endpoint`     |`endpoint.token`     |`LAUTH_ENDPOINT_TOKEN`     |`/login/token`             |Path to token endpoint.|
|`--userinfo-endpoint`  |`endpoint.userinfo`  |`LAUTH_ENDPOINT_USERINFO`  |`/login/userinfo`          |Path to userinfo endpoint.|
|`--jwks-uri`           |`endpoint.jwks`      |`LAUTH_ENDPOINT_JWKS`      |`/login/jwks`              |Path to jwks uri.|
|`--login-expire`       |`expire.login`       |`LAUTH_EXPIRE_LOGIN`       |`1h`                       |Time limit to input username and password on the login page.|
|`--code-expire`        |`expire.code`        |`LAUTH_EXPIRE_CODE`        |`5m`                       |Time limit to exchange code to `access_token` or `id_token`.|
|`--token-expire`       |`expire.token`       |`LAUTH_EXPIRE_TOKEN`       |`1d`                       |Expiration duration of `access_token` and `id_token`.|
|`--refresh-expire`     |`expire.refresh`     |`LAUTH_EXPIRE_REFRESH`     |`1w`                       |Expiration duration of `refresh_token`.<br />If set 0, `refresh_token` will not create.|
|`--sso-expire`         |`expire.sso`         |`LAUTH_EXPIRE_SSO`         |`2w`                       |Duration for don't show login page if logged in past.<br />If set 0, always ask the username and password to the end-user.|
|`--ldap`               |`ldap.server`        |`LAUTH_LDAP_SERVER`        |                           |URL of LDAP server.<br />You can include user credentials like `ldap://USER_DN:PASSW|ORD@ldap.example.com`.
|`--ldap-user`          |`ldap.user`          |`LAUTH_LDAP_USER`          |                           |User DN for connecting to LDAP.<br />You can use `DOMAIN\username` style if using ActiveDirectory.|
|`--ldap-password`      |`ldap.password`      |`LAUTH_LDAP_PASSWORD`      |                           |Password for connecting to LDAP.|
|`--ldap-base-dn`       |`ldap.base_dn`       |`LAUTH_LDAP_BASE_DN`       |same as user DC            |The base DN for search user account in LDAP like `OU=somewhere,DC=example,DC=local`.|
|`--ldap-id-attribute`  |`ldap.id_attribute`  |`LAUTH_LDAP_ID_ATTRIBUTE`  |`sAMAccountName`           |ID attribute name in LDAP.|
|`--ldap-disable-tls`   |`ldap.disable_tls`   |`LAUTH_LDAP_DISABLE_TLS`   |                           |Disable use TLS when connecting to the LDAP server. *THIS IS INSECURE.*|
|`--login-page`         |`template.login_page`|`LAUTH_TEMPLATE_LOGIN_PAGE`|                           |Templte file for login page.|
|`--error-page`         |`template.error_page`|`LAUTH_TEMPLATE_ERROR_PAGE`|                           |Templte file for error page.|
|`--metrics-path`       |`metrics.path`       |`LAUTH_METRICS_PATH`       |`/metrics`                 |Path to Prometheus metrics.|
|`--metrics-username`   |`metrics.username`   |`LAUTH_METRICS_USERNAME`   |                           |Basic auth username to access to Prometheus metrics.<br />If omit, disable authentication.|
|`--metrics-password`   |`metrics.password`   |`LAUTH_METRICS_PASSWORD`   |                           |Basic auth password to access to Prometheus metrics.<br />If omit, disable authentication.|
|`--config`             |                     |                           |                           |Load options from YAML file.|
|`--debug`              |                     |                           |                           |Enable debug output. *This is insecure* for production use.|


### gen-client sub command

``` shell
$ lauth gen-client CLIENT_ID [OPTIONS]
```

|option          |description                                                                               |
|----------------|------------------------------------------------------------------------------------------|
|`--redirect-uri`|URIs to accept redirect to.                                                               |
|`--secret`      |Client secret value. Generate random secret if omitted. *Not recommend using this option.*|
