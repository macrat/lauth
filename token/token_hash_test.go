package token_test

import (
	"testing"

	"github.com/macrat/ldapin/token"
)

func TestTokenHash(t *testing.T) {
	tests := []struct {
		Name  string
		Token string
		Hash  string
	}{
		{
			Name:  "OpenID Connect Core 1.0 Appendix A.3.",
			Token: "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
			Hash:  "77QmUPtjPfzWtF2AnpK9RQ",
		},
		{
			Name:  "OpenID Connect Core 1.0 Appendix A.4.",
			Token: "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk",
			Hash:  "LDktKdoQak3Pk0cnXxCltA",
		},
	}

	for _, tt := range tests {
		if h := token.TokenHash(tt.Token); h != tt.Hash {
			t.Errorf("%s: hash of %s is incorrect\nexpected: %s\n but got: %s", tt.Name, tt.Token, tt.Hash, h)
		}
	}
}
