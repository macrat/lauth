package api

import (
	"net/url"
	"time"
)

func (api LdapinAPI) makeAuthzTokens(req GetAuthzRequest, subject string, authTime time.Time) (*url.URL, *ErrorMessage) {
	resp := make(url.Values)

	if req.State != "" {
		resp.Set("state", req.State)
	}

	rt := ParseStringSet(req.ResponseType)

	if rt.Has("code") {
		code, err := api.TokenManager.CreateCode(
			api.Config.Issuer,
			subject,
			req.ClientID,
			req.RedirectURI,
			req.Scope,
			req.Nonce,
			authTime,
			time.Duration(*api.Config.TTL.Code),
		)
		if err != nil {
			return nil, req.makeRedirectError(err, ServerError, "failed to generate code")
		}
		resp.Set("code", code)
	}
	if rt.Has("token") {
		token, err := api.TokenManager.CreateAccessToken(
			api.Config.Issuer,
			subject,
			req.Scope,
			authTime,
			time.Duration(*api.Config.TTL.Token),
		)
		if err != nil {
			return nil, req.makeRedirectError(err, ServerError, "failed to generate access_token")
		}
		resp.Set("token_type", "Bearer")
		resp.Set("access_token", token)
		resp.Set("scope", req.Scope)
		resp.Set("expires_in", api.Config.TTL.Token.StrSeconds())
	}
	if rt.Has("id_token") {
		scope := ParseStringSet(req.Scope)
		userinfo, err := api.userinfo(subject, scope)
		if err != nil {
			return nil, req.makeRedirectError(err, ServerError, "failed to get user info")
		}

		token, err := api.TokenManager.CreateIDToken(
			api.Config.Issuer,
			subject,
			req.ClientID,
			req.Nonce,
			resp.Get("code"),
			resp.Get("access_token"),
			userinfo,
			authTime,
			time.Duration(*api.Config.TTL.Token),
		)
		if err != nil {
			return nil, req.makeRedirectError(err, ServerError, "failed to generate id_token")
		}
		resp.Set("id_token", token)
		resp.Set("expires_in", api.Config.TTL.Token.StrSeconds())
	}

	redirectURI, _ := url.Parse(req.RedirectURI)
	if rt.String() != "code" {
		redirectURI.Fragment = resp.Encode()
	} else {
		redirectURI.RawQuery = resp.Encode()
	}
	return redirectURI, nil
}
