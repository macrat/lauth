package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/url"

	"github.com/go-ldap/ldap"
)

var (
	UserNotFoundError       = fmt.Errorf("user was not found")
	MultipleUsersFoundError = fmt.Errorf("multiple users was found")
)

type LDAPConnector interface {
	Connect() (LDAPSession, error)
}

type LDAPSession interface {
	io.Closer

	LoginTest(username, password string) error
	GetUserAttributes(username string, attributes []string) (map[string][]string, error)
}

type SimpleLDAPConnector struct {
	ServerURL   *url.URL
	User        string
	Password    string
	IDAttribute string
	BaseDN      string
	DisableTLS  bool
}

func (c SimpleLDAPConnector) Connect() (LDAPSession, error) {
	conn, err := ldap.DialURL(c.ServerURL.String())
	if err != nil {
		return nil, err
	}

	err = conn.Bind(c.User, c.Password)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if c.ServerURL.Scheme != "ldaps" && !c.DisableTLS {
		err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	return &SimpleLDAPSession{
		conn:        conn,
		IDAttribute: c.IDAttribute,
		BaseDN:      c.BaseDN,
	}, nil
}

type SimpleLDAPSession struct {
	conn        *ldap.Conn
	IDAttribute string
	BaseDN      string
}

func (c *SimpleLDAPSession) Close() error {
	c.conn.Close()
	return nil
}

func (c *SimpleLDAPSession) searchUser(username string, attributes []string) (*ldap.Entry, error) {
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

func (c *SimpleLDAPSession) LoginTest(username, password string) error {
	user, err := c.searchUser(username, []string{"dn"})
	if err != nil {
		return err
	}

	return c.conn.Bind(user.DN, password)
}

func (c *SimpleLDAPSession) GetUserAttributes(username string, attributes []string) (map[string][]string, error) {
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
