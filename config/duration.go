package config

import (
	"time"
	"strconv"

	"github.com/xhit/go-str2duration/v2"
)

type Duration time.Duration

func ParseDuration(text string) (Duration, error) {
	d, err := str2duration.ParseDuration(text)
	return Duration(d), err
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
	var err error
	*d, err = ParseDuration(string(text))
	return err
}
