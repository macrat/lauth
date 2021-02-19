package token

import (
	"errors"
)

var (
	InvalidTokenError        = errors.New("invalid token")
	TokenExpiredError        = errors.New("token has already expired")
	UnexpectedIssuerError    = errors.New("unexpected issuer")
	UnexpectedAudienceError  = errors.New("unexpected audience")
	UnexpectedTokenTypeError = errors.New("unexpected token type")
	UnexpectedClientIDError  = errors.New("unexpected client_id")
)
