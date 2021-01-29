package config

import (
	"strconv"
	"time"

	"github.com/xhit/go-str2duration/v2"
)

type Duration time.Duration

func NewDuration(t time.Duration) *Duration {
	return (*Duration)(&t)
}

func ParseDuration(text string) (*Duration, error) {
	d, err := str2duration.ParseDuration(text)
	return NewDuration(d), err
}

func (d Duration) String() string {
	return d.String()
}

func (d Duration) IntSeconds() int64 {
	return int64(time.Duration(d).Seconds())
}

func (d Duration) StrSeconds() string {
	return strconv.FormatInt(d.IntSeconds(), 10)
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

func (d *Duration) UnmarshalText(text []byte) error {
	d2, err := ParseDuration(string(text))
	*d = *d2
	return err
}
