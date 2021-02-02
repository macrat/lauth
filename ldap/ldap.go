package ldap

import (
	"crypto/tls"
	"fmt"
	"io"

	"github.com/go-ldap/ldap/v3"
	"github.com/macrat/lauth/config"
)

var (
	UserNotFoundError       = fmt.Errorf("user was not found")
	MultipleUsersFoundError = fmt.Errorf("multiple users was found")
)

type Connector interface {
	Connect() (Session, error)
}

type Session interface {
	io.Closer

	LoginTest(username, password string) error
	GetUserAttributes(username string, attributes []string) (map[string][]string, error)
}

type SimpleConnector struct {
	Config *config.LDAPConfig
}

func (c SimpleConnector) Connect() (Session, error) {
	conn, err := ldap.DialURL(c.Config.Server.String())
	if err != nil {
		return nil, err
	}

	err = conn.Bind(c.Config.User, c.Config.Password)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if c.Config.Server.Scheme != "ldaps" && !c.Config.DisableTLS {
		err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	return &SimpleSession{
		conn:        conn,
		IDAttribute: c.Config.IDAttribute,
		BaseDN:      c.Config.BaseDN,
	}, nil
}

type SimpleSession struct {
	conn        *ldap.Conn
	IDAttribute string
	BaseDN      string
}

func (c *SimpleSession) Close() error {
	c.conn.Close()
	return nil
}

func (c *SimpleSession) searchUser(username string, attributes []string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		c.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2, // size limit
		0, // time limit
		false,
		fmt.Sprintf("(&(objectClass=person)(%s=%s))", c.IDAttribute, username),
		attributes,
		nil,
	)

	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) == 0 {
		return nil, UserNotFoundError
	}
	if len(res.Entries) != 1 {
		return nil, MultipleUsersFoundError
	}

	return res.Entries[0], nil
}

func (c *SimpleSession) LoginTest(username, password string) error {
	user, err := c.searchUser(username, []string{"dn"})
	if err != nil {
		return err
	}

	return c.conn.Bind(user.DN, password)
}

func (c *SimpleSession) GetUserAttributes(username string, attributes []string) (map[string][]string, error) {
	user, err := c.searchUser(username, attributes)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string)

	for _, attr := range attributes {
		result[attr] = user.GetAttributeValues(attr)
	}

	return result, nil
}
