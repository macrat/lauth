package config_test

import (
	"testing"

	"github.com/macrat/lauth/config"
)

func TestGetDCByDN(t *testing.T) {
	tests := []struct {
		DN string
		DC string
	}{
		{
			DN: "CN=someone,OU=something,DC=example,DC=com",
			DC: "DC=example,DC=com",
		},
		{
			DN: "CN=macrat,OU=users,DC=blanktar,DC=jp",
			DC: "DC=blanktar,DC=jp",
		},
		{
			DN: "OU=some,OU=where,DC=test,DC=example,DC=local",
			DC: "DC=test,DC=example,DC=local",
		},
	}

	for _, tt := range tests {
		if dc, err := config.GetDCByDN(tt.DN); err != nil {
		} else if dc != tt.DC {
			t.Errorf("failed to get DN: %s", err)
		} else if dc != tt.DC {
			t.Errorf("failed to get DN: expected %s but got %s", tt.DC, dc)
		}
	}
}
