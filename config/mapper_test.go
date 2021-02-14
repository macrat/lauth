package config_test

import (
	"reflect"
	"testing"

	"github.com/macrat/lauth/config"
)

func TestClaimType(t *testing.T) {
	tests := []struct {
		Type       string
		ParseError string
		Input      []string
		Expect     interface{}
	}{
		{"", "", []string{"hello", "world"}, "hello"},
		{"string", "", []string{"hello", "world"}, "hello"},
		{"[]string", "", []string{"hello", "world"}, []string{"hello", "world"}},
		{"number", "", []string{"hello", "world"}, float64(0)},
		{"[]number", "", []string{"hello", "world"}, []float64{0, 0}},
		{"number", "", []string{"12.34", "56.78"}, float64(12.34)},
		{"[]number", "", []string{"12.34", "56.78"}, []float64{12.34, 56.78}},

		{
			Type:       "hoge",
			ParseError: "unsupported claim type: \"hoge\"",
		},
	}

	for _, tt := range tests {
		typ := new(config.ClaimType)

		err := typ.UnmarshalText([]byte(tt.Type))
		if tt.ParseError == "" && err != nil {
			t.Errorf("failed to parse %#v: %s", tt.Type, err)
			continue
		}
		if tt.ParseError != "" {
			if err == nil {
				t.Errorf("expected failed to parse %#v but success", tt.Type)
				continue
			} else if err.Error() != tt.ParseError {
				t.Errorf("unexpected error on parse %#v: %s", tt.Type, err)
				continue
			}
		}

		got := typ.Convert(tt.Input)
		if !reflect.DeepEqual(tt.Expect, got) {
			t.Errorf("convert %#v as %s expected %#v but got %#v", tt.Input, typ, tt.Expect, got)
		}
	}
}

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
					Type:      config.CLAIM_TYPE_STRING_LIST,
				},
				"bar_attr": {
					Claim:     "bar_claim",
					Attribute: "bar_attr",
					Type:      config.CLAIM_TYPE_STRING,
				},
				"baz_attr": {
					Claim:     "baz_claim",
					Attribute: "baz_attr",
					Type:      config.CLAIM_TYPE_STRING,
				},
				"qux_attr": {
					Claim:     "qux_claim",
					Attribute: "qux_attr",
					Type:      config.CLAIM_TYPE_STRING,
				},
			},
			Expect: map[string]interface{}{
				"foo_claim": []string{"foo1", "foo2"},
				"bar_claim": "bar1",
				"baz_claim": "",
				"qux_claim": "qux1",
			},
		},
		{
			Attrs: map[string][]string{
				"num_attr":  {"123", "4.5"},
				"nums_attr": {"1.2", "3"},
				"str_attr":  {"1ab", "cd2", "3"},
				"strs_attr": {"1ab", "cd2", "3"},
				"nil_attr":  nil,
			},
			Maps: map[string]config.ClaimConfig{
				"num_attr": {
					Claim:     "num_claim",
					Attribute: "num_attr",
					Type:      config.CLAIM_TYPE_NUMBER,
				},
				"nums_attr": {
					Claim:     "nums_claim",
					Attribute: "nums_attr",
					Type:      config.CLAIM_TYPE_NUMBER_LIST,
				},
				"str_attr": {
					Claim:     "str_claim",
					Attribute: "str_attr",
					Type:      config.CLAIM_TYPE_NUMBER,
				},
				"strs_attr": {
					Claim:     "strs_claim",
					Attribute: "strs_attr",
					Type:      config.CLAIM_TYPE_NUMBER_LIST,
				},
				"nil_attr": {
					Claim:     "nil_claim",
					Attribute: "nil_attr",
					Type:      config.CLAIM_TYPE_NUMBER,
				},
			},
			Expect: map[string]interface{}{
				"num_claim":  float64(123),
				"nums_claim": []float64{1.2, 3},
				"str_claim":  float64(0),
				"strs_claim": []float64{0, 0, 3},
				"nil_claim":  float64(0),
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
