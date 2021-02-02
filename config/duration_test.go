package config_test

import (
	"testing"

	"github.com/macrat/lauth/config"
)

func TestDuration(t *testing.T) {
	d := config.Duration(0)

	tests := []string{
		"1w2d3h",
		"1w3h",
		"5m2s",
		"8h",
		"0",
	}

	for _, tt := range tests {
		if err := (&d).Set(tt); err != nil {
			t.Errorf("failed to parse %s: %s", tt, err)
		} else if s := d.String(); s != tt {
			t.Errorf("unexpected unmarshal: expected %s but got %s", tt, s)
		}
	}
}
