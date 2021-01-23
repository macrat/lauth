package main

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
		}
	}

	return result
}
