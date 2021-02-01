package main_test

import (
	"strings"
	"testing"

	"github.com/macrat/ldapin"
	"github.com/macrat/ldapin/config"
)

func TestGenClient(t *testing.T) {
	tests := []struct {
		ID     string
		Secret string
		URIs   []string
	}{
		{
			ID:     "empty",
			Secret: "",
			URIs:   []string{},
		},
		{
			ID:     "present",
			Secret: "hello world",
			URIs: []string{
				"http://localhost:*/**",
				"http://example.com/callback",
			},
		},
	}

	for _, tt := range tests {
		client, err := main.GenClient(tt.ID, tt.Secret, tt.URIs)
		if err != nil {
			t.Errorf("%s: failed to generate client config: %s", tt.ID, err)
			continue
		}

		conf := &config.Config{}
		if err := conf.ReadReader(strings.NewReader(client)); err != nil {
			t.Errorf("%s: failed to read config: %s", tt.ID, err)
		}

		if len(conf.Clients) != 1 {
			t.Errorf("%s: unexpected length clients: %d", tt.ID, len(conf.Clients))
		}

		for k, v := range conf.Clients {
			if k != tt.ID {
				t.Errorf("%s: unexpected client_id: %s", tt.ID, k)
			}

			for i, p := range v.RedirectURI {
				if tt.URIs[i] != p.String() {
					t.Errorf("%s: unexpected redirect_uri[%d]: %s", tt.ID, i, p.String())
				}
			}
		}
	}
}
