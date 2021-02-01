package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/macrat/ldapin/secret"
	"github.com/spf13/cobra"
)

var (
	clientSecret = ""
	redirectURIs = []string{}
	clientCmd    = &cobra.Command{
		Use:   "gen-client CLIENT_ID",
		Short: "Generate config for client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			client, err := GenClient(args[0], clientSecret, redirectURIs)
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

	flags.StringArrayVarP(&redirectURIs, "redirect-uri", "u", nil, "URIs to accept redirect to.")
	flags.StringVar(&clientSecret, "secret", "", "Client secret value. Generate random secret if omit. Not recommend use this option.")
}

func GenClient(clientID, secretHint string, redirectURIs []string) (string, error) {
	var sec, hash []byte
	if secretHint != "" {
		sec = []byte(secretHint)
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

	fmt.Fprintf(buf, "# Please load this by --config option.\n")
	fmt.Fprintf(buf, "# client_id = \"%s\"\n", clientID)
	fmt.Fprintf(buf, "# client_secret = \"%s\" (please don't include this line in config file)\n", sec)
	fmt.Fprintf(buf, "\n")
	fmt.Fprintf(buf, "client:\n")
	fmt.Fprintf(buf, "  %s:\n", clientID)
	fmt.Fprintf(buf, "    secret: %s\n", hash)

	if len(redirectURIs) == 0 {
		fmt.Fprintf(buf, "    redirect_uri: []\n")
	} else {
		fmt.Fprintf(buf, "    redirect_uri:\n")
		for _, u := range redirectURIs {
			fmt.Fprintf(buf, "    - %s\n", u)
		}
	}

	return string(buf.Bytes()), nil
}
