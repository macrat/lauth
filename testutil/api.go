package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/api"
	"github.com/macrat/ldapin/config"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func FindAvailTCPPort() int {
	min := 49152
	max := 65535
	for {
		port := rand.Intn(max-min+1) + min
		l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
		if err == nil {
			l.Close()
			return port
		}
	}
}

func MakeTestRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.LoadHTMLGlob("../page/html/*.tmpl")

	return router
}

func MakeConfig() *config.Config {
	conf := &config.Config{}
	port := FindAvailTCPPort()
	err := conf.ReadReader(strings.NewReader(fmt.Sprintf(`
issuer: http://localhost:%d
listen: 127.0.0.1:%d

expire:
  login: 30m
  code: 1m
  token: 1h
  refresh: 6h
  sso: 10m

endpoint:
  authorization: /authz
  token: /token
  userinfo: /userinfo
  jwks: /certs

client:
  some_client_id:
    secret: $2y$05$qA7h0boC.66l/bHndznDEeZ7MJUIIsNmD4aUeM3dtmwc2WLd0.vPa # hash of "secret for some-client"
    redirect_uri:
      - http://some-client.example.com/callback
`, port, port)))

	if err != nil {
		panic(err.Error())
	}

	return conf
}

type APITestEnvironment struct {
	App *gin.Engine
	API *api.LdapinAPI
}

func NewAPITestEnvironment(t *testing.T) *APITestEnvironment {
	t.Helper()

	router := MakeTestRouter()

	tokenManager, err := MakeTokenManager()
	if err != nil {
		t.Fatalf("failed to make jwt certs: %s", err)
	}

	api := &api.LdapinAPI{
		Connector:    LDAP,
		Config:       MakeConfig(),
		TokenManager: tokenManager,
	}
	api.SetRoutes(router)
	api.SetErrorRoutes(router)

	return &APITestEnvironment{
		App: router,
		API: api,
	}
}

func (env *APITestEnvironment) DoRequest(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	env.App.ServeHTTP(w, r)
	return w
}

func (env *APITestEnvironment) Get(path, token string, query url.Values) *httptest.ResponseRecorder {
	r, _ := http.NewRequest("GET", path+"?"+query.Encode(), nil)
	r.RemoteAddr = "[::1]:54321"

	if token != "" {
		r.Header.Set("Authorization", token)
	}

	return env.DoRequest(r)
}

func (env *APITestEnvironment) Post(path, token string, body url.Values) *httptest.ResponseRecorder {
	r, _ := http.NewRequest("POST", path, strings.NewReader(body.Encode()))
	r.RemoteAddr = "[::1]:54321"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if token != "" {
		r.Header.Set("Authorization", token)
	}

	return env.DoRequest(r)
}

func (env *APITestEnvironment) Do(method, path, token string, values url.Values) *httptest.ResponseRecorder {
	switch method {
	case "GET":
		return env.Get(path, token, values)
	case "POST":
		return env.Post(path, token, values)
	default:
		panic("unsupported method")
	}
}

type ParamsTester func(t *testing.T, query, fragment url.Values)

type RedirectTest struct {
	Request       url.Values
	Code          int
	HasLocation   bool
	AllowImplicit bool
	CheckParams   ParamsTester
	Query         url.Values
	Fragment      url.Values
}

func (env *APITestEnvironment) RedirectTest(t *testing.T, method, endpoint string, tests []RedirectTest) {
	t.Helper()

	for _, tt := range tests {
		implicitOriginal := env.API.Config.AllowImplicitFlow
		env.API.Config.AllowImplicitFlow = tt.AllowImplicit

		resp := env.Do(method, endpoint, "", tt.Request)

		env.API.Config.AllowImplicitFlow = implicitOriginal

		if resp.Code != tt.Code {
			t.Errorf("%s: expected status code %d but got %d", tt.Request.Encode(), tt.Code, resp.Code)
		}

		location := resp.Header().Get("Location")
		if !tt.HasLocation {
			if location != "" {
				t.Errorf("%s: expected has no Location but got %#v", tt.Request.Encode(), location)
			}
		} else {
			if location == "" {
				t.Errorf("%s: expected Location header but not set", tt.Request.Encode())
				continue
			}

			loc, err := url.Parse(location)
			if err != nil {
				t.Errorf("%s: failed to parse Location header: %s", tt.Request.Encode(), err)
				continue
			}

			fragment, err := url.ParseQuery(loc.Fragment)
			if err != nil {
				t.Errorf("%s: failed to parse Location fragment: %s", tt.Request.Encode(), err)
			}

			if tt.CheckParams != nil {
				tt.CheckParams(t, loc.Query(), fragment)
			} else {
				if !reflect.DeepEqual(loc.Query(), tt.Query) {
					t.Errorf("%s: redirect with unexpected query: %#v", tt.Request.Encode(), location)
				}
				if !reflect.DeepEqual(fragment, tt.Fragment) {
					t.Errorf("%s: redirect with unexpected fragment: %#v", tt.Request.Encode(), location)
				}
			}
		}
	}
}

type RawBody []byte

func (body RawBody) Bind(target interface{}) error {
	return json.Unmarshal(body, &target)
}

type JSONTester func(t *testing.T, body RawBody)

type JSONTest struct {
	Request   url.Values
	Code      int
	CheckBody JSONTester
	Body      map[string]interface{}
	Token     string
}

func (env *APITestEnvironment) JSONTest(t *testing.T, method, endpoint string, tests []JSONTest) {
	t.Helper()

	for _, tt := range tests {
		resp := env.Do(method, endpoint, tt.Token, tt.Request)

		if resp.Code != tt.Code {
			t.Errorf("%s: expected status code %d but got %d", tt.Request.Encode(), tt.Code, resp.Code)
		}

		rawBody := resp.Body.Bytes()

		if tt.CheckBody != nil {
			tt.CheckBody(t, RawBody(rawBody))
		} else {
			var body map[string]interface{}
			if err := json.Unmarshal(rawBody, &body); err != nil {
				t.Errorf("%s: failed to unmarshal response body: %s", tt.Request.Encode(), err)
			} else if !reflect.DeepEqual(body, tt.Body) {
				t.Errorf("%s: unexpected response body: %s", tt.Request.Encode(), string(rawBody))
			}
		}
	}
}

func (env *APITestEnvironment) Run(ctx context.Context) error {
	server := &http.Server{
		Addr:    env.API.Config.Issuer.Host,
		Handler: env.App,
	}

	errch := make(chan error)
	go func() {
		errch <- server.ListenAndServe()
	}()
	defer close(errch)

	select {
	case <-ctx.Done():
		server.Close()
		<-errch
		return nil
	case err := <-errch:
		return err
	}
}

func (env *APITestEnvironment) Start(t *testing.T) (stop func()) {
	t.Helper()

	ctx, stop := context.WithCancel(context.Background())
	go func() {
		err := env.Run(ctx)
		if err != nil {
			t.Fatalf("failed on test server: %s", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	return stop
}
