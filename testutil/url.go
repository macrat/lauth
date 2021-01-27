package testutil

import (
	"net/url"
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
