package config

import (
	"net/url"
)

type URL url.URL

func (u *URL) String() string {
	if u == nil {
		return ""
	}
	return (*url.URL)(u).String()
}

func (u *URL) UnmarshalText(text []byte) error {
	parsed, err := url.Parse(string(text))
	if err != nil {
		return err
	}
	*u = URL(*parsed)
	return nil
}

func (u *URL) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

func (u *URL) Set(str string) error {
	return u.UnmarshalText([]byte(str))
}

func (u *URL) Type() string {
	return "url"
}
