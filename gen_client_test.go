package main_test

import (
	"testing"
	"strings"

	"github.com/macrat/ldapin"
	"github.com/macrat/ldapin/config"
)

func TestGenClient(t *testing.T) {
	tests := []string{"", "hello"}

	for _, tt := range tests {
		client, err := main.GenClient("some-client", tt)
		if err != nil {
			t.Errorf("%#v: failed to generate client config: %s", tt, err)
			continue
		}

		conf := &config.Config{}
		if err := conf.ReadReader(strings.NewReader(client)); err != nil {
			t.Errorf("%#v: failed to read config: %s", tt, err)
		}

		if len(conf.Clients) != 1 {
			t.Errorf("%#v: unexpected length clients: %d", tt, len(conf.Clients))
		}
	}
}
