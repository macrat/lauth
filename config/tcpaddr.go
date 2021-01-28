package config

import (
	"net"
)

type TCPAddr net.TCPAddr

func (a *TCPAddr) String() string {
	return (*net.TCPAddr)(a).String()
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
