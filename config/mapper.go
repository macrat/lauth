package config

import (
	"strconv"
)

func parseNumberList(values []string) []float64 {
	result := make([]float64, len(values))
	for i, v := range values {
		result[i], _ = strconv.ParseFloat(v, 64)
	}
	return result
}

func MappingClaims(attrs map[string][]string, maps map[string]ClaimConfig) map[string]interface{} {
	result := make(map[string]interface{})

	for name, values := range attrs {
		conf := maps[name]
		switch conf.Type {
		case "string", "":
			if len(values) != 0 {
				result[conf.Claim] = values[0]
			}
		case "[]string":
			result[conf.Claim] = values
		case "number":
			if len(values) != 0 {
				result[conf.Claim], _ = strconv.ParseFloat(values[0], 64)
			}
		case "[]number":
			result[conf.Claim] = parseNumberList(values)
		}
	}

	return result
}
