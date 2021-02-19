package config

import (
	"net"
	"strconv"
)

type TCPAddr net.TCPAddr

func (a *TCPAddr) String() string {
	if a.Port == 0 {
		return ""
	} else {
		return (*net.TCPAddr)(a).String()
	}
}

func (a *TCPAddr) UnmarshalText(text []byte) error {
	parsed, err := net.ResolveTCPAddr("", string(text))
	if err != nil {
		return err
	}
	*a = TCPAddr(*parsed)
	return nil
}

func (a *TCPAddr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a *TCPAddr) Set(str string) error {
	return a.UnmarshalText([]byte(str))
}

func (a *TCPAddr) Type() string {
	return "address"
}

func DecideListenAddress(issuer *URL, listen *TCPAddr) *TCPAddr {
	if listen != nil && listen.Port != 0 {
		return listen
	}

	if issuer == nil {
		return nil
	}

	if p, err := strconv.Atoi(issuer.URL().Port()); err == nil && p != 0 {
		return &TCPAddr{
			Port: p,
		}
	}

	if issuer.Scheme == "https" {
		return &TCPAddr{
			Port: 443,
		}
	}
	return &TCPAddr{
		Port: 80,
	}
}
