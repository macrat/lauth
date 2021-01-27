package api

import (
	"fmt"
	"sort"
	"strings"
)

type StringSet []string

func ParseStringSet(raw string) *StringSet {
	var ss StringSet
	for _, s := range strings.Split(strings.TrimSpace(raw), " ") {
		s = strings.TrimSpace(s)
		if s != "" {
			ss = append(ss, s)
		}
	}
	sort.Strings(ss)
	return &ss
}

func (ss StringSet) String() string {
	return strings.Join(ss, " ")
}

func (ss StringSet) List() []string {
	return []string(ss)
}

func (ss StringSet) Has(value string) bool {
	for _, s := range ss {
		if s == value {
			return true
		}
	}
	return false
}

func (ss *StringSet) Add(value string) {
	if !ss.Has(value) {
		*ss = append(*ss, value)
	}
}

func (ss StringSet) Validate(what string, accepts []string) error {
	for _, x := range ss {
		ok := false
		for _, y := range accepts {
			if x == y {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%s \"%s\" is not supported", what, x)
		}
	}
	return nil
}
