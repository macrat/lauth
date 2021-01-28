package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type Manager struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

func NewManager(private *rsa.PrivateKey) (Manager, error) {
	return Manager{
		private: private,
		public:  private.Public().(*rsa.PublicKey),
	}, nil
}

func GenerateManager() (Manager, error) {
	pri, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return Manager{}, err
	}
	return NewManager(pri)
}

func NewManagerFromFile(file io.Reader) (Manager, error) {
	raw, err := ioutil.ReadAll(file)
	if err != nil {
		return Manager{}, err
	}

	pri, err := jwt.ParseRSAPrivateKeyFromPEM(raw)
	if err != nil {
		return Manager{}, err
	}

	return NewManager(pri)
}

func (m Manager) PublicKey() *rsa.PublicKey {
	return m.public
}

func (m Manager) KeyID() uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceX500, x509.MarshalPKCS1PublicKey(m.public))
}

func (m Manager) create(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.KeyID().String()
	return token.SignedString(m.private)
}

func (m Manager) parse(token string, claims jwt.Claims) (*jwt.Token, error) {
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return m.public, nil
	})

	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, InvalidTokenError
	}
	return parsed, nil
}
