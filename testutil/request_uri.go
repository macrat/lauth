package testutil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func (env *APITestEnvironment) ServeRequestURI(t *testing.T) *httptest.Server {
	someClient := []byte(SomeClientRequestObject(t, map[string]interface{}{
		"iss":          "some_client_id",
		"aud":          env.API.Config.Issuer.String(),
		"redirect_uri": "http://some-client.example.com/callback",
	}))

	m := http.NewServeMux()

	m.HandleFunc("/empty", func(w http.ResponseWriter, r *http.Request) {})

	m.HandleFunc("/server-error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	m.HandleFunc("/not-jwt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not valid jwt"))
	})

	m.HandleFunc("/some-client/correct", func(w http.ResponseWriter, r *http.Request) {
		w.Write(someClient)
	})

	return httptest.NewServer(m)
}
