package config

import (
	"strings"
)

type ParseErrorSet []error

func (es ParseErrorSet) Error() string {
	ss := make([]string, len(es)+1)
	ss[0] = "Failed to parse options:"

	for i, e := range es {
		ss[i+1] = "  " + e.Error()
	}

	return strings.Join(ss, "\n") + "\n\nPlease see --help for more information."
}
