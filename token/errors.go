package token

import (
	"fmt"
)

var (
	InvalidTokenError        = fmt.Errorf("invalid token")
	UnexpectedIssuerError    = fmt.Errorf("unexpected issuer")
	UnexpectedAudienceError  = fmt.Errorf("unexpected audience")
	UnexpectedTokenTypeError = fmt.Errorf("unexpected token type")
	UnexpectedClientIDError  = fmt.Errorf("unexpected client_id")
)
