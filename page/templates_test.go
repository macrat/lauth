package page_test

import (
	"bytes"
	"html/template"
	"io/ioutil"
	"os"
	"testing"

	"github.com/macrat/lauth/config"
	"github.com/macrat/lauth/page"
)

func Render(t *testing.T, tmpl *template.Template, name string) string {
	t.Helper()

	buf := bytes.NewBuffer([]byte{})

	if err := tmpl.ExecuteTemplate(buf, name, map[string]map[string]string{"error": {"Reason": ""}}); err != nil {
		t.Fatalf("failed to render: %s", err)
	}

	if len(buf.Bytes()) == 0 {
		t.Fatalf("failed to render: rendered HTML size was 0")
	}

	return string(buf.Bytes())
}

func MakeTestFile(t *testing.T, content string) string {
	t.Helper()

	f, err := ioutil.TempFile("", "*")
	if err != nil {
		t.Fatalf("failed to prepare test file: %s", err)
	}
	_, err = f.Write([]byte(content))
	if err != nil {
		t.Fatalf("failed to write test file: %s", err)
	}

	return f.Name()
}

func TestLoad(t *testing.T) {
	tmpl, err := page.Load(config.TemplateConfig{LoginPage: "", ErrorPage: ""})
	if err != nil {
		t.Fatalf("failed to load templates: %s", err)
	}

	if Render(t, tmpl, "login.tmpl") == "[[this is test login page]]" {
		t.Errorf("expected normal builtin login page but got test page")
	}

	if Render(t, tmpl, "logout.tmpl") == "[[this is test logged out page]]" {
		t.Errorf("expected normal builtin logout page but got test page")
	}

	if Render(t, tmpl, "error.tmpl") == "[[this is test error page]]" {
		t.Errorf("expected normal builtin error page but got test page")
	}

	loginPage := MakeTestFile(t, "[[this is test login page]]")
	defer os.Remove(loginPage)
	logoutPage := MakeTestFile(t, "[[this is test logged out page]]")
	defer os.Remove(logoutPage)
	errorPage := MakeTestFile(t, "[[this is test error page]]")
	defer os.Remove(errorPage)

	tmpl, err = page.Load(config.TemplateConfig{
		LoginPage:  loginPage,
		LogoutPage: logoutPage,
		ErrorPage:  errorPage,
	})
	if err != nil {
		t.Fatalf("failed to load templates: %s", err)
	}

	if Render(t, tmpl, "login.tmpl") != "[[this is test login page]]" {
		t.Errorf("expected test login page but got normal builtin page")
	}

	if Render(t, tmpl, "logout.tmpl") != "[[this is test logged out page]]" {
		t.Errorf("expected test logout page but got normal builtin page")
	}

	if Render(t, tmpl, "error.tmpl") != "[[this is test error page]]" {
		t.Errorf("expected test error page but got normal builtin page")
	}
}
