package config_test

import (
	"net"
	"testing"

	"github.com/macrat/lauth/config"
)

func TestDecideListenAddress(t *testing.T) {
	tests := []struct {
		Issuer *config.URL
		Listen *config.TCPAddr
		Expect string
	}{
		{
			Issuer: &config.URL{Scheme: "http", Host: "localhost:8000"},
			Listen: &config.TCPAddr{
				IP:   net.ParseIP("127.1.2.3"),
				Port: 1234,
			},
			Expect: "127.1.2.3:1234",
		},
		{
			Issuer: &config.URL{Scheme: "http", Host: "localhost:8000"},
			Listen: nil,
			Expect: ":8000",
		},
		{
			Issuer: &config.URL{Scheme: "http", Host: "localhost"},
			Listen: &config.TCPAddr{
				IP:   net.ParseIP("127.1.2.3"),
				Port: 1234,
			},
			Expect: "127.1.2.3:1234",
		},
		{
			Issuer: &config.URL{Scheme: "http", Host: "localhost"},
			Listen: nil,
			Expect: ":80",
		},
		{
			Issuer: &config.URL{Scheme: "https", Host: "localhost"},
			Listen: nil,
			Expect: ":443",
		},
		{
			Issuer: &config.URL{Scheme: "http", Host: "localhost:8000"},
			Listen: &config.TCPAddr{},
			Expect: ":8000",
		},
	}

	for _, tt := range tests {
		resp := config.DecideListenAddress(tt.Issuer, tt.Listen)
		if resp.String() != tt.Expect {
			t.Errorf("issuer=%s,listen=%s: expected %#v but got %#v", tt.Issuer, tt.Listen, tt.Expect, resp)
		}
	}
}
