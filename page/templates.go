package page

//go:generate statik -f -src html

import (
	"html/template"
	"io/ioutil"
	"os"

	"github.com/macrat/lauth/config"
	"github.com/rakyll/statik/fs"

	_ "github.com/macrat/lauth/page/statik"
)

func Load(conf config.TemplateConfig) (*template.Template, error) {
	statikFs, err := fs.New()
	if err != nil {
		return nil, err
	}

	t := template.New("")

	err = fs.Walk(statikFs, "/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		file, err := statikFs.Open(path)
		if err != nil {
			return err
		}

		raw, err := ioutil.ReadAll(file)
		if err != nil {
			return err
		}

		_, err = t.New(path[1:]).Parse(string(raw))
		return err
	})
	if err != nil {
		return nil, err
	}

	if conf.LoginPage != "" {
		raw, err := ioutil.ReadFile(conf.LoginPage)
		if err != nil {
			return nil, err
		}
		_, err = t.Lookup("login.tmpl").Parse(string(raw))
		if err != nil {
			return nil, err
		}
	}

	if conf.ErrorPage != "" {
		raw, err := ioutil.ReadFile(conf.ErrorPage)
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
