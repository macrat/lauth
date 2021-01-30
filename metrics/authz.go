package metrics

var (
	Authz = NewEndpointMetrics("authz", []string{"client_id", "response_type", "scope", "prompt", "method", "authn_by"})
)

func init() {
	Authz.MustRegister()
}

func StartAuthz(method string) *Context {
	c := Authz.Start()
	c.Set("method", method)
	return c
}

func StartGetAuthz() *Context {
	return StartAuthz("GET")
}

func StartPostAuthz() *Context {
	return StartAuthz("POST")
}
