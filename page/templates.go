package page

import (
	"embed"
	"html/template"
	"io"
	"os"
	"path"

	"github.com/macrat/lauth/config"
)

//go:embed html/*.tmpl
var templates embed.FS

func Load(conf config.TemplateConfig) (*template.Template, error) {
	t := template.New("")

	fis, err := templates.ReadDir("html")
	if err != nil {
		return nil, err
	}

	for _, fi := range fis {
		file, err := templates.Open(path.Join("html", fi.Name()))
		if err != nil {
			return nil, err
		}

		raw, err := io.ReadAll(file)
		if err != nil {
			return nil, err
		}

		_, err = t.New(fi.Name()).Parse(string(raw))
		if err != nil {
			return nil, err
		}
	}

	if conf.LoginPage != "" {
		raw, err := os.ReadFile(conf.LoginPage)
		if err != nil {
			return nil, err
		}
		_, err = t.Lookup("login.tmpl").Parse(string(raw))
		if err != nil {
			return nil, err
		}
	}

	if conf.LogoutPage != "" {
		raw, err := os.ReadFile(conf.LogoutPage)
		if err != nil {
			return nil, err
		}
		_, err = t.Lookup("logout.tmpl").Parse(string(raw))
		if err != nil {
			return nil, err
		}
	}

	if conf.ErrorPage != "" {
		raw, err := os.ReadFile(conf.ErrorPage)
		if err != nil {
			return nil, err
		}
		_, err = t.Lookup("error.tmpl").Parse(string(raw))
		if err != nil {
			return nil, err
		}
	}

	return t, nil
}
