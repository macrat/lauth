package token_test

import (
	"crypto/rsa"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/macrat/ldapin/config"
	"github.com/macrat/ldapin/token"
	"gopkg.in/square/go-jose.v2"
)

func TestTokenManager_JWKs(t *testing.T) {
	key := []byte(`{"N":9039033174548737757763349592897156144561122672663310040527422749240235483764145068221544478116474003849802702552171874980704343213690082946294562313062351,"E":65537,"D":5319122837628311035993428756270072232039065825319029174710172661964980418188819709056314986164416886910365660013037940292482363553824204460767500099664769,"Primes":[90684377024022860670302322975263435567145900146334636010284461526289736903983,99675748692128536481253841181163633680197292236257288280408147545857650272097],"Precomputed":{"Dp":31761740546705231301800807506815949768959015395257110258023246866265691455117,"Dq":56275117526854265198939124121400668474311915559664859906058896002933898678881,"Qinv":15094748279451631901966083981262161035874636170480727131058444517630620616644,"CRTValues":[]}}`)
	keyID := "afec5549-e6bd-5a9f-9d4e-df2768b1bbbc"

	var pri rsa.PrivateKey
	json.Unmarshal(key, &pri)

	manager, err := token.NewManager(&pri)
	if err != nil {
		t.Fatalf("failed to load test key: %s", err)
	}

	jwks, err := manager.JWKs()
	if err != nil {
		t.Errorf("failed to generate JWKs: %s", err)
	}
	expected := []token.JWK{
		{KeyID: keyID, Use: "sig", Algorithm: "RS256", KeyType: "RSA", E: "AQAB", N: "rJXfsn14r_G2hX23sYzd4hM57l3dhebASzUQKc6nV3ozrcICRUr4gPIZ-OnzsoFlMBpaf9Lxwwm8TByrfdXHzw"},
	}
	if !reflect.DeepEqual(jwks, expected) {
		t.Errorf("unexpected jwks: %#v", jwks)
	}

	if encJwks, err := json.Marshal(jwks[0]); err != nil {
		t.Errorf("failed to marshal JWKs: %s", err)
	} else {
		decJwks := new(jose.JSONWebKey)
		if err := decJwks.UnmarshalJSON(encJwks); err != nil {
			t.Errorf("failed to unmarshal JWKs: %s", err)
		} else if !decJwks.Valid() {
			t.Errorf("unmarshalled JWKs is not valid")
		} else if !decJwks.Key.(*rsa.PublicKey).Equal(manager.PublicKey()) {
			t.Errorf("unmarshalled public key is not equals original key")
		}
	}

	idToken, err := manager.CreateIDToken(&config.URL{Scheme: "https", Host: "localhost"}, "someone", "something", "", "code", "token", nil, time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate id_token: %s", err)
	}

	jwt.Parse(idToken, func(tok *jwt.Token) (interface{}, error) {
		kid, ok := tok.Header["kid"]
		if !ok {
			t.Fatalf("failed to get kid from id_token")
		}
		if strkid, ok := kid.(string); !ok {
			t.Fatalf("kid is not string")
		} else if strkid != keyID {
			t.Fatalf("unexpected kid: %s", kid)
		}

		return pri, nil
	})
}
