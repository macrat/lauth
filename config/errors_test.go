package config_test

import (
	"errors"
	"testing"

	"github.com/macrat/lauth/config"
)

func TestParseErrorSet(t *testing.T) {
	tests := []struct {
		Set    config.ParseErrorSet
		Expect string
	}{
		{
			Set: config.ParseErrorSet{
				errors.New("hoge"),
			},
			Expect: "Failed to parse options:\n  hoge\n\nPlease see --help for more information.",
		},
		{
			Set: config.ParseErrorSet{
				errors.New("hoge"),
				errors.New("fuga"),
			},
			Expect: "Failed to parse options:\n  hoge\n  fuga\n\nPlease see --help for more information.",
		},
	}

	for _, tt := range tests {
		if tt.Set.Error() != tt.Expect {
			t.Errorf("unexpected error string\nexpected:\n%s\nbut got:\n%s", tt.Set.Error(), tt.Expect)
		}
	}
}
