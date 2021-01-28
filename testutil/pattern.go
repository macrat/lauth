package testutil

import (
	"github.com/macrat/ldapin/config"
)

func MustParsePattern(pattern string) config.Pattern {
	var p config.Pattern
	(&p).UnmarshalText([]byte(pattern))
	return p
}
