Lauth
=====

The simple OpenID Provider for LDAP like a Microsoft ActiveDirectory(AD).

![Lauth can translate LDAP and OAuth2/OpenID Connect](./images/lauth.svg)

## Usage

Start server,

``` shell
$ USER="CN=username,OU=somewhere,DC=example,DC=local"
$ lauth --ldap ldap://${USER}:${PASSWORD}@ldap.example.com --ldap-base-dn OU=somewhere,DC=example,DC=com

$ lauth --ldap ldap://${DOMAIN}%5c${USERNAME}:${PASSWORD}@ldap.example.com --ldap-base-dn OU=somewhere,DC=example,DC=com  # for ActiveDirectory.
```

And access to API.

``` shell
$ curl http://localhost:8000/.well-known/openid-configuration | jq
{
  "authorization_endpoint": "http:/localhost:8000/login",
  "claims_supported": [
    "name",
    "given_name",
    "family_name",
    "email",
    "phone_number",
    "groups",
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "typ",
    "auth_time"
  ],
  "display_values_supported": [
    "page"
  ],
  "grant_types_supported": [
    "authorization_code"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "issuer": "http://localhost:8000",
  "jwks_uri": "http:/localhost:8000/login/certs",
  "response_modes_supported": [
    "query",
    "fragment"
  ],
  "response_types_supported": [
    "code",
    "token",
    "id_token",
    "code token",
    "code id_token",
    "token id_token",
    "code token id_token"
  ],
  "scopes_supported": [
    "profile",
    "email",
    "phone",
    "groups",
    "openid"
  ],
  "subject_types_supported": [
    "public"
  ],
  "token_endpoint": "http:/localhost:8000/login/token",
  "userinfo_endpoint": "http:/localhost:8000/login/userinfo"
}
