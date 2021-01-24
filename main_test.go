package main_test

import (
	"net"
	"net/url"
	"testing"

	"github.com/macrat/ldapin"
)

func MustParseURL(u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		panic(err.Error())
	}
	return parsed
}

func MustParseQuery(q string) url.Values {
	parsed, err := url.ParseQuery(q)
	if err != nil {
		panic(err.Error())
	}
	return parsed
}

func TestDecideListenAddress(t *testing.T) {
	tests := []struct {
		Issuer *url.URL
		Listen *net.TCPAddr
		Expect string
	}{
		{
			Issuer: MustParseURL("http://localhost:8000"),
			Listen: &net.TCPAddr{
				IP:   net.ParseIP("127.1.2.3"),
				Port: 1234,
			},
			Expect: "127.1.2.3:1234",
		},
		{
			Issuer: MustParseURL("http://localhost:8000"),
			Listen: nil,
			Expect: ":8000",
		},
		{
			Issuer: MustParseURL("http://localhost"),
			Listen: &net.TCPAddr{
				IP:   net.ParseIP("127.1.2.3"),
				Port: 1234,
			},
			Expect: "127.1.2.3:1234",
		},
		{
			Issuer: MustParseURL("http://localhost"),
			Listen: nil,
			Expect: ":80",
		},
		{
			Issuer: MustParseURL("https://localhost"),
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
