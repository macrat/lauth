package errors

var (
	// OpenID errors
	AccessDenied            Reason = "access_denied"
	InvalidClient           Reason = "invalid_client"
	InvalidGrant            Reason = "invalid_grant"
	InvalidRequest          Reason = "invalid_request"
	InvalidRequestObject    Reason = "invalid_request_object"
	InvalidScope            Reason = "invalid_scope"
	InvalidToken            Reason = "invalid_token"
	RequestNotSupported     Reason = "request_not_supported"
	RequestURINotSupported  Reason = "request_uri_not_supported"
	ServerError             Reason = "server_error"
	TemporarilyUnavailable  Reason = "temporarily_unavailable"
	UnauthorizedClient      Reason = "unauthorized_client"
	UnsupportedGrantType    Reason = "unsupported_grant_type"
	UnsupportedResponseType Reason = "unsupported_response_type"

	// original errors
	MethodNotAllowed Reason = "method_not_allowed"
	PageNotFound     Reason = "page_not_found"
)

type Reason string

func (e Reason) String() string {
	return string(e)
}
