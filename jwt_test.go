package main_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/macrat/ldapin"
)

func makeJWTManager() (main.JWTManager, error) {
	pri, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return main.JWTManager{}, err
	}
	return main.NewJWTManager(pri)
}

func TestCodeToken(t *testing.T) {
	jwtManager, err := makeJWTManager()
	if err != nil {
		t.Fatalf("failed to generate JWTManager: %s", err)
	}

	issuer := &main.URL{Scheme: "http", Host: "localhost:8000"}

	code, err := jwtManager.CreateCode(issuer, "someone", "something", "openid profile", "", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate code: %s", err)
	}

	claims, err := jwtManager.ParseCode(code)
	if err != nil {
		t.Fatalf("failed to parse code: %s", err)
	}

	if err = claims.Validate(issuer); err != nil {
		t.Errorf("failed to validate code: %s", err)
	}

	if err = claims.Validate(&main.URL{Host: "another-issuer"}); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != main.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}

	accessToken, _ := jwtManager.ParseAccessToken(code)
	if err = accessToken.Validate(issuer); err == nil {
		t.Fatalf("must be failed to validation code as access token but success")
	} else if err != main.UnexpectedTokenTypeError {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestAccessToken(t *testing.T) {
	jwtManager, err := makeJWTManager()
	if err != nil {
		t.Fatalf("failed to generate JWTManager: %s", err)
	}

	issuer := &main.URL{Scheme: "http", Host: "localhost:8000"}

	token, err := jwtManager.CreateAccessToken(issuer, "someone", "openid profile", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}

	claims, err := jwtManager.ParseAccessToken(token)
	if err != nil {
		t.Fatalf("failed to parse access token: %s", err)
	}

	if err = claims.Validate(issuer); err != nil {
		t.Errorf("failed to validate access token: %s", err)
	}

	if err = claims.Validate(&main.URL{Host: "another-issuer"}); err == nil {
		t.Errorf("must be failed if issuer is incorrect but success")
	} else if err != main.UnexpectedIssuerError {
		t.Errorf("unexpected error: %s", err)
	}

	code, _ := jwtManager.ParseCode(token)
	if err = code.Validate(issuer); err == nil {
		t.Fatalf("must be failed to validation access token as code but success")
	} else if err != main.UnexpectedTokenTypeError {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestIDToken(t *testing.T) {
	jwtManager, err := makeJWTManager()
	if err != nil {
		t.Fatalf("failed to generate JWTManager: %s", err)
	}

	issuer := &main.URL{Scheme: "http", Host: "localhost:8000"}

	_, err = jwtManager.CreateIDToken(issuer, "someone", "something", "", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %s", err)
	}
}

func TestJWTManager_JWKs(t *testing.T) {
	key := []byte(`{"N":9039033174548737757763349592897156144561122672663310040527422749240235483764145068221544478116474003849802702552171874980704343213690082946294562313062351,"E":65537,"D":5319122837628311035993428756270072232039065825319029174710172661964980418188819709056314986164416886910365660013037940292482363553824204460767500099664769,"Primes":[90684377024022860670302322975263435567145900146334636010284461526289736903983,99675748692128536481253841181163633680197292236257288280408147545857650272097],"Precomputed":{"Dp":31761740546705231301800807506815949768959015395257110258023246866265691455117,"Dq":56275117526854265198939124121400668474311915559664859906058896002933898678881,"Qinv":15094748279451631901966083981262161035874636170480727131058444517630620616644,"CRTValues":[]}}`)
	keyID := "afec5549-e6bd-5a9f-9d4e-df2768b1bbbc"

	var pri rsa.PrivateKey
	json.Unmarshal(key, &pri)

	manager, err := main.NewJWTManager(&pri)
	if err != nil {
		t.Fatalf("failed to load test key: %s", err)
	}

	jwks, err := manager.JWKs()
	if err != nil {
		t.Errorf("failed to generate JWKs: %s", err)
	}
	expected := []main.JWK{
		{KeyID: keyID, Use: "sig", Algorithm: "RS256", KeyType: "RSA", E: "AQAB", N: "rJXfsn14r_G2hX23sYzd4hM57l3dhebASzUQKc6nV3ozrcICRUr4gPIZ-OnzsoFlMBpaf9Lxwwm8TByrfdXHzw"},
	}
	if !reflect.DeepEqual(jwks, expected) {
		t.Errorf("unexpected jwks: %#v", jwks)
	}

	token, err := manager.CreateIDToken(&main.URL{Scheme: "https", Host: "localhost"}, "someone", "something", "", time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate id_token: %s", err)
	}

	jwt.Parse(token, func(tok *jwt.Token) (interface{}, error) {
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
