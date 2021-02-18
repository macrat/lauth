package testutil

import (
	"errors"
	"io"

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

func FindInputsByHTML(body io.Reader) (map[string]string, error) {
	nodes, err := html.Parse(body)
	if err != nil {
		return nil, err
	}

	inputs := make(map[string]string)
	findInputs(nodes, inputs)

	return inputs, nil
}

func FindRequestObjectByHTML(body io.Reader) (string, error) {
	inputs, err := FindInputsByHTML(body)
	if err != nil {
		return "", err
	}

	if req := inputs["request"]; req == "" {
		return "", errors.New("request is not in the form")
	} else {
		return req, nil
	}
}
