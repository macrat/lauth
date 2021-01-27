package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/macrat/ldapin/api"
	"github.com/macrat/ldapin/testutil"
)

func ServeErrorMessageRedirect(t *testing.T, msg api.ErrorMessage) *httptest.ResponseRecorder {
	t.Helper()

	router := testutil.MakeTestRouter()

	router.GET("/", func(c *gin.Context) {
		msg.Redirect(c)
	})

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, r)

	return w
}

func TestErrorMessage_Redirect(t *testing.T) {
	tests := []struct {
		Msg        api.ErrorMessage
		NoRedirect bool
		Query      url.Values
		Fragment   url.Values
	}{
		{
			Msg: api.ErrorMessage{
				Reason:      "some_reason",
				Description: "hello world",
			},
			NoRedirect: true,
		},
		{
			Msg: api.ErrorMessage{
				RedirectURI: testutil.MustParseURL("/relative/path"),
				Reason:      "some_reason",
				Description: "hello world",
			},
			NoRedirect: true,
		},
		{
			Msg: api.ErrorMessage{
				RedirectURI:  testutil.MustParseURL("http://localhost:3000/redirect"),
				ResponseType: "code",
				State:        "hello world",
				Reason:       "something_wrong",
				Description:  "this is something wrong!",
			},
			Query:    testutil.MustParseQuery("state=hello world&error=something_wrong&error_description=this is something wrong!"),
			Fragment: url.Values{},
		},
		{
			Msg: api.ErrorMessage{
				RedirectURI:  testutil.MustParseURL("http://localhost:3000/redirect"),
				ResponseType: "code token",
				State:        "hello world",
				Reason:       "something_wrong",
				Description:  "this is something wrong!",
			},
			Query:    url.Values{},
			Fragment: testutil.MustParseQuery("state=hello world&error=something_wrong&error_description=this is something wrong!"),
		},
		{
			Msg: api.ErrorMessage{
				RedirectURI:  testutil.MustParseURL("http://localhost:3000/redirect"),
				ResponseType: "code",
				Reason:       "something_wrong",
			},
			Query:    testutil.MustParseQuery("error=something_wrong"),
			Fragment: url.Values{},
		},
		{
			Msg: api.ErrorMessage{
				RedirectURI:  testutil.MustParseURL("http://localhost:3000/redirect"),
				ResponseType: "token",
				Reason:       "something_wrong",
			},
			Query:    url.Values{},
			Fragment: testutil.MustParseQuery("error=something_wrong"),
		},
		{
			Msg: api.ErrorMessage{
				RedirectURI: testutil.MustParseURL("http://localhost:3000/redirect"),
				Reason:      "something_wrong",
			},
			Query:    testutil.MustParseQuery("error=something_wrong"),
			Fragment: url.Values{},
		},
		{
			Msg: api.ErrorMessage{
				RedirectURI:  testutil.MustParseURL("http://localhost:3000/redirect"),
				ResponseType: "code invalid",
				Reason:       "something_wrong",
			},
			Query:    url.Values{},
			Fragment: testutil.MustParseQuery("error=something_wrong"),
		},
	}

	for i, tt := range tests {
		resp := ServeErrorMessageRedirect(t, tt.Msg)
		if tt.NoRedirect {
			if resp.Code != http.StatusBadRequest {
				t.Errorf("%d: unexpected response code: %d", i, resp.Code)
			}
			if resp.Header().Get("Content-Type") != "text/html; charset=utf-8" {
				t.Errorf("%d: unexpected content-type: %s", i, resp.Header().Get("Content-Type"))
			}
		} else {
			if resp.Code != http.StatusFound {
				t.Errorf("%d: unexpected response code: %d", i, resp.Code)
			}

			location, err := url.Parse(resp.Header().Get("Location"))
			if err != nil {
				t.Errorf("%d: failed to parse redirect url: %s", i, err)
				continue
			}

			if !reflect.DeepEqual(location.Query(), tt.Query) {
				t.Errorf("%d: unexpected redirect query: %#v", i, location.String())
			}

			fragment, err := url.ParseQuery(location.Fragment)
			if err != nil {
				t.Errorf("%d: failed to parse fragment: %s", i, err)
			}
			if !reflect.DeepEqual(fragment, tt.Fragment) {
				t.Errorf("%d: unexpected redirect fragment: %#v", i, location.String())
			}
		}
	}
}
