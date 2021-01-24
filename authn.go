package main

import (
	"net/url"
	"time"
)

func MakeAuthnTokens(jwt JWTManager, config *LdapinConfig, req GetAuthnRequest, subject string) (*url.URL, *ErrorMessage) {
	resp := make(url.Values)

	if req.State != "" {
		resp.Set("state", req.State)
	}

	rt := ParseStringSet(req.ResponseType)

	if rt.Has("code") {
		code, err := jwt.CreateCode(
			config.Issuer,
			subject,
			req.ClientID,
			req.Scope,
			req.Nonce,
			time.Now(),
			time.Duration(config.TTL.Code),
		)
		if err != nil {
			return nil, req.makeError(err, "server_error", "failed to generate code")
		}
		resp.Set("code", code)
	}
	if rt.Has("token") {
		token, err := jwt.CreateAccessToken(
			config.Issuer,
			subject,
			req.Scope,
			time.Now(),
			time.Duration(config.TTL.Token),
		)
		if err != nil {
			return nil, req.makeError(err, "server_error", "failed to generate access_token")
		}
		resp.Set("token_type", "Bearer")
		resp.Set("access_token", token)
		resp.Set("scope", req.Scope)
		resp.Set("expires_in", config.TTL.Token.StrSeconds())
	}
	if rt.Has("id_token") {
		token, err := jwt.CreateIDToken(
			config.Issuer,
			subject,
			req.ClientID,
			req.Nonce,
			time.Now(),
			time.Duration(config.TTL.Token),
		)
		if err != nil {
			return nil, req.makeError(err, "server_error", "failed to generate id_token")
		}
		resp.Set("id_token", token)
		resp.Set("expires_in", config.TTL.Token.StrSeconds())
	}

	redirectURI, _ := url.Parse(req.RedirectURI)
	if rt.String() != "code" {
		redirectURI.Fragment = resp.Encode()
	} else {
		redirectURI.RawQuery = resp.Encode()
	}
	return redirectURI, nil
}
