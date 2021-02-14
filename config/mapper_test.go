package config_test

import (
	"reflect"
	"testing"

	"github.com/macrat/lauth/config"
)

func TestMappingClaims(t *testing.T) {
	tests := []struct {
		Attrs  map[string][]string
		Maps   map[string]config.ClaimConfig
		Expect map[string]interface{}
	}{
		{
			Attrs: map[string][]string{
				"foo_attr": {"foo1", "foo2"},
				"bar_attr": {"bar1"},
				"baz_attr": nil,
				"qux_attr": {"qux1", "qux2"},
			},
			Maps: map[string]config.ClaimConfig{
				"foo_attr": {
					Claim:     "foo_claim",
					Attribute: "foo_attr",
					Type:      "[]string",
				},
				"bar_attr": {
					Claim:     "bar_claim",
					Attribute: "bar_attr",
					Type:      "string",
				},
				"baz_attr": {
					Claim:     "baz_claim",
					Attribute: "baz_attr",
				},
				"qux_attr": {
					Claim:     "qux_claim",
					Attribute: "qux_attr",
				},
			},
			Expect: map[string]interface{}{
				"foo_claim": []string{"foo1", "foo2"},
				"bar_claim": "bar1",
				"qux_claim": "qux1",
			},
		},
		{
			Attrs: map[string][]string{
				"num_attr":  {"123", "4.5"},
				"nums_attr": {"1.2", "3"},
				"str_attr":  {"1ab", "cd2", "3"},
				"strs_attr": {"1ab", "cd2", "3"},
			},
			Maps: map[string]config.ClaimConfig{
				"num_attr": {
					Claim:     "num_claim",
					Attribute: "num_attr",
					Type:      "number",
				},
				"nums_attr": {
					Claim:     "nums_claim",
					Attribute: "nums_attr",
					Type:      "[]number",
				},
				"str_attr": {
					Claim:     "str_claim",
					Attribute: "str_attr",
					Type:      "number",
				},
				"strs_attr": {
					Claim:     "strs_claim",
					Attribute: "strs_attr",
					Type:      "[]number",
				},
			},
			Expect: map[string]interface{}{
				"num_claim":  float64(123),
				"nums_claim": []float64{1.2, 3},
				"str_claim":  float64(0),
				"strs_claim": []float64{0, 0, 3},
			},
		},
	}
	for i, tt := range tests {
		result := config.MappingClaims(tt.Attrs, tt.Maps)

		if !reflect.DeepEqual(result, tt.Expect) {
			t.Errorf("%d: unexpected mapping result:\nexpected: %#v\nbut got: %#v", i, tt.Expect, result)
		}
	}
}
