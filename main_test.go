package main_test

import (
	"net"
	"net/url"
	"testing"

	"github.com/macrat/ldapin"
	"github.com/macrat/ldapin/testutil"
)

func TestDecideListenAddress(t *testing.T) {
	tests := []struct {
		Issuer *url.URL
		Listen *net.TCPAddr
		Expect string
	}{
		{
			Issuer: testutil.MustParseURL("http://localhost:8000"),
			Listen: &net.TCPAddr{
				IP:   net.ParseIP("127.1.2.3"),
				Port: 1234,
			},
			Expect: "127.1.2.3:1234",
		},
		{
			Issuer: testutil.MustParseURL("http://localhost:8000"),
			Listen: nil,
			Expect: ":8000",
		},
		{
			Issuer: testutil.MustParseURL("http://localhost"),
			Listen: &net.TCPAddr{
				IP:   net.ParseIP("127.1.2.3"),
				Port: 1234,
			},
			Expect: "127.1.2.3:1234",
		},
		{
			Issuer: testutil.MustParseURL("http://localhost"),
			Listen: nil,
			Expect: ":80",
		},
		{
			Issuer: testutil.MustParseURL("https://localhost"),
			Listen: nil,
			Expect: ":443",
		},
	}

	for _, tt := range tests {
		resp := main.DecideListenAddress(tt.Issuer, tt.Listen)
		if resp != tt.Expect {
			t.Errorf("issuer=%s,listen=%s: expected %#v but got %#v", tt.Issuer, tt.Listen, tt.Expect, resp)
		}
	}
}
