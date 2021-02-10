package main_test

import (
	"strings"
	"testing"

	"github.com/macrat/lauth"
	"github.com/macrat/lauth/config"
)

func TestGenClient(t *testing.T) {
	tests := []main.GenClientConfig{
		{
			ID:                "empty",
			Name:              "",
			IconURL:           "",
			Secret:            "",
			URIs:              []string{},
			AllowImplicitFlow: false,
		},
		{
			ID:      "all_present",
			Name:    "All Present",
			IconURL: "https://localhost/image.png",
			Secret:  "hello world",
			URIs: []string{
				"http://localhost:*/**",
				"http://example.com/callback",
			},
			AllowImplicitFlow: true,
		},
		{
			ID:      "quote string",
			Name:    `need "quote" string`,
			IconURL: "",
			Secret:  "hello world",
			URIs: []string{
				"'quote' \"me\"",
				"http://example.com\n/\ncallback",
			},
			AllowImplicitFlow: true,
		},
	}

	for _, tt := range tests {
		client, err := main.GenClient(tt)
		if err != nil {
			t.Errorf("%s: failed to generate client config: %s", tt.ID, err)
			continue
		}

		conf := &config.Config{}
		if err := conf.ReadReader(strings.NewReader(client)); err != nil {
			t.Errorf("%s: failed to read config: %s", tt.ID, err)
		}

		t.Log(client)

		if len(conf.Clients) != 1 {
			t.Errorf("%s: unexpected length clients: %d", tt.ID, len(conf.Clients))
		}

		for k, v := range conf.Clients {
			if k != tt.ID {
				t.Errorf("%s: unexpected client_id: %s", tt.ID, k)
			}

			if (tt.Name == "" && v.Name != tt.ID) || (tt.Name != "" && v.Name != tt.Name) {
				t.Errorf("%s: unexpected name: %s", tt.ID, v.Name)
			}

			if v.IconURL != tt.IconURL {
				t.Errorf("%s: unexpected icon_url: %s", tt.ID, v.IconURL)
			}

			for i, p := range v.RedirectURI {
				if tt.URIs[i] != p.String() {
					t.Errorf("%s: unexpected redirect_uri[%d]: %s", tt.ID, i, p.String())
				}
			}

			if v.AllowImplicitFlow != tt.AllowImplicitFlow {
				t.Errorf("%s: unexpected allow_implicit_flow: %t", tt.ID, v.AllowImplicitFlow)
			}
		}
	}
}
