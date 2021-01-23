package main_test

import (
	"testing"
	"net/url"
	"reflect"
	"net/http"
	"net/http/httptest"

	"github.com/macrat/ldapin"
	"github.com/gin-gonic/gin"
)

func MustParseURL(u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		panic(err.Error())
	}
	return parsed
}

func MustParseQuery(q string) url.Values {
	parsed, err := url.ParseQuery(q)
	if err != nil {
		panic(err.Error())
	}
	return parsed
}

func ServeErrorMessageRedirect(t *testing.T, msg main.ErrorMessage) *httptest.ResponseRecorder {
	t.Helper()

	router := MakeTestRouter()

	router.GET("/", func(c *gin.Context) {
		msg.Redirect(c)
	})

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, r)

	return w
}

func TestErrorMessage_Redirect(t *testing.T) {
	nonRedirect := ServeErrorMessageRedirect(t, main.ErrorMessage{
		Reason: "some_reason",
		Description: "hello world",
	})
	if nonRedirect.Code != http.StatusBadRequest {
		t.Errorf("unexpected response code: %d", nonRedirect.Code)
	}
	if nonRedirect.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("unexpected content-type: %s", nonRedirect.Header().Get("Content-Type"))
	}

	tests := []struct{
		Msg      main.ErrorMessage
		Query    url.Values
		Fragment url.Values
	}{
		{
			Msg: main.ErrorMessage{
				RedirectURI: MustParseURL("http://localhost:3000/redirect"),
				ResponseType: "code",
				State: "hello world",
				Reason: "something_wrong",
				Description: "this is something wrong!",
			},
			Query: MustParseQuery("state=hello world&error=something_wrong&error_description=this is something wrong!"),
			Fragment: url.Values{},
		},
		{
			Msg: main.ErrorMessage{
				RedirectURI: MustParseURL("http://localhost:3000/redirect"),
				ResponseType: "code token",
				State: "hello world",
				Reason: "something_wrong",
				Description: "this is something wrong!",
			},
			Query: url.Values{},
			Fragment: MustParseQuery("state=hello world&error=something_wrong&error_description=this is something wrong!"),
		},
		{
			Msg: main.ErrorMessage{
				RedirectURI: MustParseURL("http://localhost:3000/redirect"),
				ResponseType: "code",
				Reason: "something_wrong",
			},
			Query: MustParseQuery("error=something_wrong"),
			Fragment: url.Values{},
		},
	}

	for i, tt := range tests {
		resp := ServeErrorMessageRedirect(t, tt.Msg)
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
