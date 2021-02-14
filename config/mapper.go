package config

import (
	"fmt"
	"strconv"
)

type ClaimType string

const (
	CLAIM_TYPE_STRING      ClaimType = "string"
	CLAIM_TYPE_STRING_LIST           = "[]string"
	CLAIM_TYPE_NUMBER                = "number"
	CLAIM_TYPE_NUMBER_LIST           = "[]number"
)

func (t ClaimType) String() string {
	return string(t)
}

func (t *ClaimType) UnmarshalText(text []byte) error {
	switch ClaimType(string(text)) {
	case CLAIM_TYPE_STRING, "":
		*t = CLAIM_TYPE_STRING
	case CLAIM_TYPE_STRING_LIST, CLAIM_TYPE_NUMBER, CLAIM_TYPE_NUMBER_LIST:
		*t = ClaimType(string(text))
	default:
		return fmt.Errorf("unsupported claim type: %#v", string(text))
	}
	return nil
}

func parseNumberList(values []string) []float64 {
	result := make([]float64, len(values))
	for i, v := range values {
		result[i], _ = strconv.ParseFloat(v, 64)
	}
	return result
}

func (t ClaimType) Convert(values []string) interface{} {
	switch t {
	case CLAIM_TYPE_STRING:
		if len(values) == 0 {
			return ""
		} else {
			return values[0]
		}
	case CLAIM_TYPE_STRING_LIST:
		return values

	case CLAIM_TYPE_NUMBER:
		if len(values) == 0 {
			return float64(0)
		} else {
			result, _ := strconv.ParseFloat(values[0], 64)
			return result
		}
	case CLAIM_TYPE_NUMBER_LIST:
		return parseNumberList(values)

	default:
		return nil
	}
}

func MappingClaims(attrs map[string][]string, maps map[string]ClaimConfig) map[string]interface{} {
	result := make(map[string]interface{})

	for name, values := range attrs {
		conf := maps[name]
		result[conf.Claim] = conf.Type.Convert(values)
	}

	return result
}
