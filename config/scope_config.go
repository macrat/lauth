package config

type ScopeConfig map[string][]ClaimConfig

func (sc ScopeConfig) ScopeNames() []string {
	var ss []string
	for scope := range sc {
		ss = append(ss, scope)
	}
	return ss
}

func (sc ScopeConfig) AllClaims() []string {
	var claims []string
	for _, scope := range sc {
		for _, claim := range scope {
			claims = append(claims, claim.Claim)
		}
	}
	return claims
}

func (sc ScopeConfig) AttributesFor(scopes []string) []string {
	var claims []string

	for _, scopeName := range scopes {
		if scope, ok := sc[scopeName]; ok {
			for _, x := range scope {
				claims = append(claims, x.Attribute)
			}
		}
	}

	return claims
}

func (sc ScopeConfig) ClaimMapFor(scopes []string) map[string]ClaimConfig {
	claims := make(map[string]ClaimConfig)

	for _, scopeName := range scopes {
		if scope, ok := sc[scopeName]; ok {
			for _, x := range scope {
				claims[x.Attribute] = x
			}
		}
	}

	return claims
}
