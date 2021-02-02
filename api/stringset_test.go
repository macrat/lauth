package api_test

import (
	"testing"

	"github.com/macrat/lauth/api"
)

func TestStringSet(t *testing.T) {
	a := api.ParseStringSet("hello world")
	b := api.ParseStringSet("world hello")

	if a.String() != b.String() {
		t.Error("\"hello world\" and \"world hello\" is must be equals but not")
	}

	if !a.Has("hello") {
		t.Error("\"hello world\" must has \"hello\" but not")
	}

	if !a.Has("world") {
		t.Error("\"hello world\" must has \"world\" but not")
	}

	if a.Has("foobar") {
		t.Error("\"hello world\" must has not \"foobar\" but had")
	}
	a.Add("foobar")
	if !a.Has("foobar") {
		t.Error("\"hello world\" must has \"foobar\" but not")
	}
	if a.String() == b.String() {
		t.Error("a and b is must be not equals now but equals yet")
	}

	err := a.Validate("something", []string{"hello", "world", "foobar", "hogefuga"})
	if err != nil {
		t.Errorf("expected valid but not: %s", err)
	}

	err = a.Validate("something", []string{"hello", "world"})
	if err == nil {
		t.Errorf("expected not valid but valid")
	} else if err.Error() != "something \"foobar\" is not supported" {
		t.Errorf("unexpected error causes: %s", err)
	}
}
