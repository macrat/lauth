package main_test

import (
	"reflect"
	"testing"

	"github.com/macrat/ldapin"
)

func TestMappingClaims(t *testing.T) {
	tests := []struct {
		Attrs  map[string][]string
		Maps   map[string]main.ClaimConfig
		Expect map[string]interface{}
	}{
		{
			Attrs: map[string][]string{
				"foo_attr": {"foo1", "foo2"},
				"bar_attr": {"bar1"},
				"baz_attr": nil,
				"qux_attr": {"qux1", "qux2"},
			},
			Maps: map[string]main.ClaimConfig{
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
	}
	for i, tt := range tests {
		result := main.MappingClaims(tt.Attrs, tt.Maps)

		if !reflect.DeepEqual(result, tt.Expect) {
			t.Errorf("%d: unexpected mapping result: %#v", i, result)
		}
	}
}
