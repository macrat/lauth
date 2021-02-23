package api_test

import (
	"net/http"
	"testing"

	"github.com/macrat/lauth/testutil"
)

func TestOptionsUserInfo(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	tests := []struct {
		Name   string
		Origin string
		Code   int
		CORS   string
	}{
		{
			Name:   "without origin",
			Origin: "",
			Code:   http.StatusOK,
			CORS:   "",
		},
		{
			Name:   "with valid origin",
			Origin: "http://implicit-client.example.com",
			Code:   http.StatusOK,
			CORS:   "http://implicit-client.example.com",
		},
		{
			Name:   "with invalid origin",
			Origin: "http://some-client.example.com",
			Code:   http.StatusForbidden,
			CORS:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			req, err := http.NewRequest("OPTIONS", "/userinfo", nil)
			if err != nil {
				t.Fatalf("failed to make request: %s", err)
			}
			req.Header.Add("Origin", tt.Origin)

			resp := env.DoRequest(req)
			if resp.Code != tt.Code {
				t.Fatalf("status code: expected %d but got %d", tt.Code, resp.Code)
			}

			if cors := resp.Header().Get("Access-Control-Allow-Origin"); cors != tt.CORS {
				t.Errorf("Access-Control-Allow-Origin: expected %#v but got %#v", tt.CORS, cors)
			}
		})
	}
}
