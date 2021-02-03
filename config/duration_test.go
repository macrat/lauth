package config_test

import (
	"fmt"
	"testing"

	"github.com/macrat/lauth/config"
)

func TestDuration(t *testing.T) {
	d := config.Duration(0)

	tests := []struct {
		Input   string
		Output  string
		Seconds int64
	}{
		{"1w2d3h", "1w2d3h", ((7+2)*24 + 3) * 60 * 60},
		{"1w3h", "1w3h", (7*24 + 3) * 60 * 60},
		{"5m2s", "5m2s", 5*60 + 2},
		{"8h", "8h", 8 * 60 * 60},
		{"2h0m", "2h", 2 * 60 * 60},
		{"70m", "1h10m", 70 * 60},
		{"0d0m", "0", 0},
		{"0", "0", 0},
	}

	for _, tt := range tests {
		if err := (&d).Set(tt.Input); err != nil {
			t.Errorf("failed to parse %s: %s", tt.Input, err)
			continue
		}
		if s := d.String(); s != tt.Output {
			t.Errorf("%s: unexpected unmarshal: expected %s but got %s", tt.Input, tt.Output, s)
		}
		if i := d.IntSeconds(); i != tt.Seconds {
			t.Errorf("%s: unexpected int seconds: expected %d but got %d", tt.Input, tt.Seconds, i)
		}
		if s := d.StrSeconds(); s != fmt.Sprint(tt.Seconds) {
			t.Errorf("%s: unexpected int seconds: expected %#v but got %#v", tt.Input, tt.Seconds, s)
		}
	}
}
