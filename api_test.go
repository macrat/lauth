package main_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin"
)

var (
	dummyLdapinConfig = main.LdapinConfig{
		Issuer:         "http://localhost:8000",
		CodeExpiresIn:  1 * time.Minute,
		TokenExpiresIn: 1 * time.Hour,
		Endpoints: main.EndpointConfig{
			BasePath: "/",
			Authn:    "/authn",
			Token:    "/token",
			Userinfo: "/userinfo",
			Jwks:     "/certs",
		},
		Scopes: main.ScopeConfig{
			"profile": {
				{Claim: "name", Attribute: "displayName", Type: "string"},
				{Claim: "given_name", Attribute: "givenName", Type: "string"},
				{Claim: "family_name", Attribute: "sn", Type: "string"},
			},
			"email": {
				{Claim: "email", Attribute: "mail", Type: "string"},
			},
			"phone": {
				{Claim: "phone_number", Attribute: "telephoneNumber", Type: "string"},
			},
			"groups": {
				{Claim: "groups", Attribute: "memberOf", Type: "[]string"},
			},
		},
	}
)

func makeTestRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.LoadHTMLGlob("html/*.tmpl")

	return router
}

type APITestEnvironment struct {
	App *gin.Engine
	API *main.LdapinAPI
}

func NewAPITestEnvironment(t *testing.T) *APITestEnvironment {
	t.Helper()

	router := makeTestRouter()

	jwt, err := makeJWTManager()
	if err != nil {
		t.Fatalf("failed to make jwt certs: %s", err)
	}

	api := &main.LdapinAPI{
		Connector:  dummyLDAP,
		Config:     dummyLdapinConfig,
		JWTManager: jwt,
	}
	api.SetRoutes(router)

	return &APITestEnvironment{
		App: router,
		API: api,
	}
}

func (env *APITestEnvironment) Get(path string, query url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", path+"?"+query.Encode(), nil)

	env.App.ServeHTTP(w, r)

	return w
}

func (env *APITestEnvironment) Post(path string, body url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("POST", path, strings.NewReader(body.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	env.App.ServeHTTP(w, r)

	return w
}
