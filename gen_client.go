package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/macrat/lauth/secret"
	"github.com/spf13/cobra"
)

type GenClientConfig struct {
	ID                string
	Name              string
	IconURL           string
	Secret            string
	URIs              []string
	AllowImplicitFlow bool
}

var (
	genClientConfig = GenClientConfig{}
	clientCmd       = &cobra.Command{
		Use:   "gen-client CLIENT_ID",
		Short: "Generate config for client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			genClientConfig.ID = args[0]

			if genClientConfig.Name == "" {
				genClientConfig.Name = args[0]
			}

			client, err := GenClient(genClientConfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to hash secret: %s", err)
				os.Exit(1)
			}

			fmt.Print(client)
		},
	}
)

func init() {
	cmd.AddCommand(clientCmd)

	flags := clientCmd.Flags()
	flags.SortFlags = false

	flags.StringVarP(&genClientConfig.Name, "name", "n", "", "Display name of this client. Use same value as client ID in default.")
	flags.StringVarP(&genClientConfig.IconURL, "icon-url", "i", "", "Icon image URL for displaying on the login page.")
	flags.StringArrayVarP(&genClientConfig.URIs, "redirect-uri", "u", nil, "URIs to accept redirect to.")
	flags.StringVar(&genClientConfig.Secret, "secret", "", "Client secret value. Generate random secret if omit. Not recommend use this option.")
	flags.BoolVar(&genClientConfig.AllowImplicitFlow, "allow-implicit-flow", false, "Allow implicit and hybrid flow for this client.")
}

func quoteString(str string) string {
	b, _ := json.Marshal(str)
	return string(b)
}

func GenClient(conf GenClientConfig) (string, error) {
	var sec, hash []byte
	if conf.Secret != "" {
		sec = []byte(conf.Secret)
		h, err := secret.Hash(sec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to hash secret: %s", err)
		}
		hash = h
	} else {
		s, err := secret.Generate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate secret: %s", err)
		}
		sec, hash = s.Secret, s.Hash
	}

	buf := bytes.NewBuffer([]byte{})

	fmt.Fprintf(buf, "# Client registration of \"%s\".\n", conf.ID)
	fmt.Fprintf(buf, "[client.%s]\n", quoteString(conf.ID))
	fmt.Fprintf(buf, "\n")
	fmt.Fprintf(buf, "# Display name of this client.\n")
	fmt.Fprintf(buf, "name = %s\n", quoteString(conf.Name))
	fmt.Fprintf(buf, "\n")
	fmt.Fprintf(buf, "# Icon image URL for displaying on the login page.\n")
	if conf.IconURL == "" {
		fmt.Fprintf(buf, "#icon_url = \"https://example.com/icon.png\"\n")
	} else {
		fmt.Fprintf(buf, "icon_url = %s\n", quoteString(conf.IconURL))
	}
	fmt.Fprintf(buf, "\n")
	fmt.Fprintf(buf, "# client_secret is \"%s\" (please remove this line after copy secret)\n", sec)
	fmt.Fprintf(buf, "secret = \"%s\"\n", hash)
	fmt.Fprintf(buf, "\n")
	fmt.Fprintf(buf, "# Allow use implicit and hybrid flow for this client.\n")
	fmt.Fprintf(buf, "allow_implicit_flow = %t\n", conf.AllowImplicitFlow)
	fmt.Fprintf(buf, "\n")
	fmt.Fprintf(buf, "# URIs for redirect after login or logout.\n")
	fmt.Fprintf(buf, "redirect_uri = [\n")
	for _, u := range conf.URIs {
		fmt.Fprintf(buf, "  %s,\n", quoteString(u))
	}
	fmt.Fprintf(buf, "]\n")

	return string(buf.Bytes()), nil
}
