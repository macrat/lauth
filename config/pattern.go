package config

import (
	"github.com/gobwas/glob"
)

type Pattern struct {
	matcher glob.Glob
	pattern string
}

func (p Pattern) MarshalText() ([]byte, error) {
	return []byte(p.pattern), nil
}

func (p *Pattern) UnmarshalText(text []byte) error {
	pat, err := glob.Compile(string(text), '/')
	if err != nil {
		return err
	}

	(*p).pattern = string(text)
	(*p).matcher = pat

	return nil
}

func (p Pattern) String() string {
	return p.pattern
}

func (p Pattern) Match(u *URL) bool {
	return p.matcher.Match(u.String())
}

type PatternSet []Pattern

func (ps PatternSet) Match(u *URL) bool {
	for _, p := range ps {
		if p.Match(u) {
			return true
		}
	}
	return false
}
