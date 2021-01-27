package page_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/macrat/ldapin/testutil"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

func findInputs(parent *html.Node, inputs map[string]string) {
	for node := parent.FirstChild; node != nil; node = node.NextSibling {
		if node.Type == html.ElementNode {
			if node.DataAtom == atom.Input {
				name := ""
				value := ""

				for _, attr := range node.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "value":
						value = attr.Val
					}
				}

				inputs[name] = value
			}

			findInputs(node, inputs)
		}
	}
}

func TestLoginForm_value_passing(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"test_client"},
		"redirect_uri":  {"http://localhost:3000"},
		"scope":         {"openid profile"},
		"state":         {"this-is-state"},
		"nonce":         {"noncenoncenonce"},
	}
	resp := env.Get("/authz", "", params)

	if resp.Code != http.StatusOK {
		t.Fatalf("failed to render login page (status code = %d)", resp.Code)
	}

	nodes, err := html.Parse(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse login page: %s", err)
	}

	inputs := make(map[string]string)
	findInputs(nodes, inputs)

	for key := range params {
		if v, ok := inputs[key]; !ok {
			t.Errorf("parameter %s is missing in form", key)
		} else if params.Get(key) != v {
			t.Errorf("parameter %s is expected %s but got %s", key, params.Get(key), v)
		}
	}

	if _, ok := inputs["username"]; !ok {
		t.Errorf("username is missing in form")
	}

	if _, ok := inputs["password"]; !ok {
		t.Errorf("password is missing in form")
	}
}
