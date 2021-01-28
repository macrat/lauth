package config_test

import (
	"testing"

	"github.com/macrat/ldapin/config"
)

func TestPattern(t *testing.T) {
	tests := []struct {
		Pattern string
		Input   string
		Match   bool
	}{
		{
			Pattern: "http*://example.com/login/*",
			Input:   "http://example.com/login/callback",
			Match:   true,
		},
		{
			Pattern: "http*://example.com/login/*",
			Input:   "https://example.com/login/",
			Match:   true,
		},
		{
			Pattern: "http*://example.com/login/*",
			Input:   "http://example.com/login",
			Match:   false,
		},
		{
			Pattern: "http*://example.com/login/*",
			Input:   "http://example.com/login/callback/oidc",
			Match:   false,
		},
		{
			Pattern: "http*://example.com/login/**",
			Input:   "http://example.com/login/callback/oidc",
			Match:   true,
		},
	}

	for _, tt := range tests {
		p := &config.Pattern{}

		if err := p.UnmarshalText([]byte(tt.Pattern)); err != nil {
			t.Errorf("failed to parse pattern %#v: %s", tt.Pattern, err)
		}

		if p.Match(tt.Input) != tt.Match {
			if tt.Match {
				t.Errorf("expected %s is match to %s but not", tt.Input, tt.Pattern)
			} else {
				t.Errorf("expected %s is not match to %s but not", tt.Input, tt.Pattern)
			}
		}
	}
}
