package integration_test

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/macrat/lauth/testutil"
	"golang.org/x/oauth2"
)

func TestSSOLoginTest(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	stop := env.Start(t)
	defer stop()

	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		t.Fatalf("failed to prepare cookie jar: %s", err)
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}

	openIDConfig := env.API.Config.OpenIDConfiguration()

	oauth2config := oauth2.Config{
		ClientID:     "implicit_client_id",
		ClientSecret: "secret for implicit-client",
		RedirectURL:  "http://implicit-client.example.com/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  openIDConfig.AuthorizationEndpoint,
			TokenURL: openIDConfig.TokenEndpoint,
		},
		Scopes: []string{oidc.ScopeOpenID},
	}

	// ---------- First login --------------------
	authURL, err := url.Parse(oauth2config.AuthCodeURL("this is state"))
	if err != nil {
		t.Fatalf("failed to make auth code URL: %s", err)
	}
	authQuery := authURL.Query()
	authQuery.Set("response_type", "id_token")
	authQuery.Set("nonce", "this is nonce")
	authURL.RawQuery = authQuery.Encode()

	resp, err := client.Get(authURL.String())
	if err != nil {
		t.Fatalf("failed to get authorization URL: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	request, err := testutil.FindRequestObjectByHTML(resp.Body)
	if err != nil {
		t.Fatalf("failed to get request object: %s", err)
	}

	authQuery = url.Values{
		"response_type": {"id_token"},
		"client_id":     {"implicit_client_id"},
		"request":       {request},
		"username":      {"macrat"},
		"password":      {"foobar"},
	}
	authURL.RawQuery = ""

	resp, err = client.Post(authURL.String(), "application/x-www-form-urlencoded", strings.NewReader(authQuery.Encode()))
	if err != nil {
		t.Fatalf("failed to post to authorization URL: %s", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unexpected response code: %d", resp.StatusCode)
	}

	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse location: %s", err)
	}

	fragment, err := url.ParseQuery(loc.Fragment)
	if err != nil {
		t.Fatalf("failed to parse fragment: %s", err)
	}

	if errMsg := fragment.Get("error"); errMsg != "" {
		t.Fatalf("unexpected error message: error=%#v error_description=%#v", errMsg, fragment.Get("error_description"))
	}

	idToken := fragment.Get("id_token")
	if idToken == "" {
		t.Fatalf("failed to get id_token")
	}

	// ---------- Second login (using SSO) --------------------
	resp, err = client.Get(oauth2config.AuthCodeURL("another state"))
	if err != nil {
		t.Fatalf("failed to fetch authorization URL: %s", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unexpected response code: %d", resp.StatusCode)
	}

	loc, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse location: %s", err)
	}

	if errMsg := loc.Query().Get("error"); errMsg != "" {
		t.Fatalf("unexpected error message: error=%#v error_description=%#v", errMsg, loc.Query().Get("error_description"))
	}

	// ---------- 3rd login (using SSO / consent prompt) --------------------
	authURL, err = url.Parse(oauth2config.AuthCodeURL("another state2"))
	if err != nil {
		t.Fatalf("failed to make auth code URL: %s", err)
	}
	authQuery = authURL.Query()
	authQuery.Set("prompt", "consent")
	authURL.RawQuery = authQuery.Encode()

	resp, err = client.Get(authURL.String())
	if err != nil {
		t.Fatalf("failed to fetch authorization URL: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response code: %d", resp.StatusCode)
	}
	inputs, err := testutil.FindInputsByHTML(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse consent prompt page: %s", err)
	}

	authQuery = url.Values{}
	for k, v := range inputs {
		authQuery.Add(k, v)
	}
	authURL.RawQuery = ""

	resp, err = client.Post(authURL.String(), "application/x-www-form-urlencoded", strings.NewReader(authQuery.Encode()))
	if err != nil {
		t.Fatalf("failed to fetch authorization URL: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unexpected response code: %d", resp.StatusCode)
	}
	loc, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse location: %s", err)
	}

	if errMsg := loc.Query().Get("error"); errMsg != "" {
		t.Fatalf("unexpected error message: error=%#v error_description=%#v", errMsg, loc.Query().Get("error_description"))
	}

	// ---------- Logout --------------------
	resp, err = client.Get(fmt.Sprintf("%s/logout?id_token_hint=%s", env.API.Config.Issuer, idToken))
	if err != nil {
		t.Fatalf("failed to fetch logout URL: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response code: %d", resp.StatusCode)
	}

	// ---------- 4th login (show login form because already logged out) --------------------
	resp, err = client.Get(oauth2config.AuthCodeURL("yet another state"))
	if err != nil {
		t.Fatalf("failed to fetch authorization URL: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response code: %d", resp.StatusCode)
	}
}
