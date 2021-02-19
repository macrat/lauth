package config

import (
	"fmt"
	"strconv"
	"time"

	"github.com/xhit/go-str2duration/v2"
)

type Duration time.Duration

func ParseDuration(text string) (Duration, error) {
	d, err := str2duration.ParseDuration(text)
	return Duration(d), err
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

func (d Duration) String() string {
	if d == 0 {
		return "0"
	}

	units := []struct {
		Unit   string
		Thresh time.Duration
	}{
		{"w", 7 * 24 * time.Hour},
		{"d", 24 * time.Hour},
		{"h", time.Hour},
		{"m", time.Minute},
		{"s", time.Second},
	}

	remain := time.Duration(d)
	str := ""
	for _, u := range units {
		if remain >= u.Thresh {
			str += fmt.Sprintf("%d%s", remain/u.Thresh, u.Unit)
			remain = remain % u.Thresh
		}
	}
	return str
}

func (d Duration) IntSeconds() int64 {
	return int64(d.Duration().Seconds())
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

func (d *Duration) Set(str string) error {
	return d.UnmarshalText([]byte(str))
}

func (d Duration) Type() string {
	return "duration"
}
