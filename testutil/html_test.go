package testutil_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/macrat/lauth/testutil"
)

func TestFindInputsByHTML(t *testing.T) {
	html := strings.NewReader(`<html><input name="hello" value="world" /><input type=hidden name=foo value=bar></html>`)

	inputs, err := testutil.FindInputsByHTML(html)
	if err != nil {
		t.Fatalf("failed to parse HTML: %s", err)
	}

	expect := map[string]string{
		"hello": "world",
		"foo":   "bar",
	}
	if !reflect.DeepEqual(inputs, expect) {
		t.Errorf("failed to get inputs\nexpected: %#v\n but got: %#v", expect, inputs)
	}
}
