package config

import (
	"fmt"
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

func (d *Duration) Set(str string) error {
	return d.UnmarshalText([]byte(str))
}

func (d Duration) Type() string {
	return "duration"
}
